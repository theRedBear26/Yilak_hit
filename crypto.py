"""
shared/crypto.py
================
Core cryptographic primitives for the Secure Chat Application.

Implements:
  - Ephemeral ECDH (X25519) key exchange  → Perfect Forward Secrecy
  - HKDF-SHA256 key derivation
  - AES-256-GCM authenticated encryption
  - ECDSA (P-256) digital signatures      → Message authenticity
  - Key fingerprint generation            → MITM resistance
  - Message integrity via GCM tag         → Built-in to AES-GCM

Architecture mirrors Signal Protocol's approach:
  Each session gets fresh ephemeral keys, so compromise of long-term
  identity keys does NOT expose past messages (PFS).
"""

import os
import json
import base64
import hashlib
import hmac
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1, EllipticCurvePrivateKey, EllipticCurvePublicKey,
    generate_private_key as ec_generate_private_key,
    ECDSA
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


# ──────────────────────────────────────────────────────────────────────────────
# 1. IDENTITY KEYS  (long-lived ECDSA P-256 for signatures)
# ──────────────────────────────────────────────────────────────────────────────

class IdentityKey:
    """
    Long-term signing key pair (ECDSA over P-256 / secp256r1).
    Used ONLY for signing — never for encryption.
    """

    def __init__(self, private_key: EllipticCurvePrivateKey = None):
        if private_key is None:
            self._private = ec_generate_private_key(SECP256R1(), default_backend())
        else:
            self._private = private_key
        self._public: EllipticCurvePublicKey = self._private.public_key()

    # ── Serialisation ──────────────────────────────────────────────────────

    def private_bytes(self) -> bytes:
        return self._private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def public_bytes(self) -> bytes:
        return self._public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def public_bytes_raw(self) -> bytes:
        """Compact uncompressed EC point (65 bytes)."""
        return self._public.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

    @classmethod
    def from_private_pem(cls, pem: bytes) -> "IdentityKey":
        private = serialization.load_pem_private_key(pem, password=None)
        return cls(private_key=private)

    @classmethod
    def public_from_pem(cls, pem: bytes) -> EllipticCurvePublicKey:
        return serialization.load_pem_public_key(pem)

    # ── Signing / Verification ─────────────────────────────────────────────

    def sign(self, data: bytes) -> bytes:
        """Returns DER-encoded ECDSA signature."""
        return self._private.sign(data, ECDSA(hashes.SHA256()))

    @staticmethod
    def verify(public_key: EllipticCurvePublicKey, data: bytes, signature: bytes) -> bool:
        """Returns True if signature is valid, False otherwise (never raises)."""
        try:
            public_key.verify(signature, data, ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    # ── Fingerprint ────────────────────────────────────────────────────────

    def fingerprint(self) -> str:
        """
        SHA-256 of the raw public key, formatted as hex pairs separated by ':'.
        Users compare fingerprints out-of-band to defeat MITM attacks.
        Example: "AB:12:CD:34:..."
        """
        digest = hashlib.sha256(self.public_bytes_raw()).digest()
        return ':'.join(f'{b:02X}' for b in digest)


# ──────────────────────────────────────────────────────────────────────────────
# 2. EPHEMERAL SESSION KEYS  (X25519 ECDH for key agreement)
# ──────────────────────────────────────────────────────────────────────────────

class EphemeralKey:
    """
    Short-lived X25519 key pair for one session / message batch.

    X25519 is Curve25519 optimised for Diffie-Hellman.
    Generate fresh keys for EVERY session → Perfect Forward Secrecy.
    If a session key leaks, only that session is compromised.
    """

    def __init__(self):
        self._private: X25519PrivateKey = X25519PrivateKey.generate()
        self._public: X25519PublicKey  = self._private.public_key()

    def public_bytes(self) -> bytes:
        """32-byte raw public key (X25519 canonical form)."""
        return self._public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def public_b64(self) -> str:
        return base64.b64encode(self.public_bytes()).decode()

    def exchange(self, peer_public_bytes: bytes) -> bytes:
        """
        Perform X25519 DH and return the 32-byte shared secret.
        The shared secret is the same on both sides:
          Alice: exchange(Bob_pub)  == Bob: exchange(Alice_pub)
        """
        peer_pub = X25519PublicKey.from_public_bytes(peer_public_bytes)
        return self._private.exchange(peer_pub)


# ──────────────────────────────────────────────────────────────────────────────
# 3. KEY DERIVATION  (HKDF-SHA256)
# ──────────────────────────────────────────────────────────────────────────────

def derive_session_keys(
    shared_secret: bytes,
    salt: bytes,
    info: bytes = b"secure-chat-v1"
) -> Tuple[bytes, bytes]:
    """
    Derive two independent 32-byte keys from the DH shared secret:
      - encryption_key  → AES-256-GCM
      - mac_key         → HMAC-SHA256 (additional integrity layer)

    HKDF (RFC 5869) is the standard KDF for this purpose.
    Using separate keys for encryption and MAC is a security best practice.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,        # 32 bytes enc_key + 32 bytes mac_key
        salt=salt,
        info=info,
        backend=default_backend()
    )
    key_material = hkdf.derive(shared_secret)
    enc_key = key_material[:32]
    mac_key = key_material[32:]
    return enc_key, mac_key


# ──────────────────────────────────────────────────────────────────────────────
# 4. SYMMETRIC ENCRYPTION  (AES-256-GCM)
# ──────────────────────────────────────────────────────────────────────────────

def encrypt_message(key: bytes, plaintext: str, associated_data: bytes = b"") -> dict:
    """
    Encrypt plaintext with AES-256-GCM.

    AES-GCM provides:
      - Confidentiality  (AES-CTR cipher)
      - Integrity        (GHASH authentication tag, 128-bit)
      - Authenticity     (authenticated encryption)

    Parameters
    ----------
    key             : 32-byte AES key
    plaintext       : message string to encrypt
    associated_data : additional authenticated data (e.g. sender ID, timestamp)
                      NOT encrypted but IS integrity-protected.

    Returns
    -------
    dict with base64-encoded nonce, ciphertext+tag
    """
    aesgcm = AESGCM(key)
    nonce  = os.urandom(12)   # 96-bit nonce — NEVER reuse with same key!
    ct     = aesgcm.encrypt(nonce, plaintext.encode(), associated_data or None)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode()
    }


def decrypt_message(key: bytes, payload: dict, associated_data: bytes = b"") -> str:
    """
    Decrypt AES-256-GCM payload.
    Raises ValueError if integrity check fails (tampered message).
    """
    aesgcm = AESGCM(key)
    nonce  = base64.b64decode(payload["nonce"])
    ct     = base64.b64decode(payload["ciphertext"])
    try:
        plaintext = aesgcm.decrypt(nonce, ct, associated_data or None)
        return plaintext.decode()
    except Exception:
        raise ValueError("Decryption failed — message may have been tampered with!")


# ──────────────────────────────────────────────────────────────────────────────
# 5. SIGNED ENVELOPE  (tie together encryption + signature)
# ──────────────────────────────────────────────────────────────────────────────

def create_signed_message(
    plaintext: str,
    enc_key: bytes,
    identity_key: IdentityKey,
    sender: str,
    timestamp: str,
) -> dict:
    """
    Build a fully authenticated, encrypted message envelope.

    Structure:
      {
        encrypted: { nonce, ciphertext },   ← AES-256-GCM encrypted payload
        signature: <base64 ECDSA sig>,      ← signs hash(nonce + ciphertext)
        sender:    <username>,
        timestamp: <ISO-8601>
      }

    The signature covers the ciphertext bytes so an attacker cannot:
      - Swap ciphertexts between messages (replay attack)
      - Modify the sender field without detection
    """
    # Associated data binds sender+timestamp to the ciphertext
    aad = f"{sender}|{timestamp}".encode()

    encrypted = encrypt_message(enc_key, plaintext, associated_data=aad)

    # Sign: ECDSA over SHA256(nonce_bytes || ciphertext_bytes)
    signing_input = (
        base64.b64decode(encrypted["nonce"]) +
        base64.b64decode(encrypted["ciphertext"]) +
        aad
    )
    signature = identity_key.sign(signing_input)

    return {
        "encrypted": encrypted,
        "signature": base64.b64encode(signature).decode(),
        "sender":    sender,
        "timestamp": timestamp,
        "public_key": base64.b64encode(identity_key.public_bytes()).decode()
    }


def verify_and_decrypt(
    envelope: dict,
    enc_key: bytes,
    expected_sender: str = None
) -> Tuple[str, bool]:
    """
    Verify the digital signature then decrypt.

    Returns (plaintext, signature_valid).
    Raises ValueError if decryption fails (integrity broken).
    """
    encrypted  = envelope["encrypted"]
    sender     = envelope["sender"]
    timestamp  = envelope["timestamp"]
    signature  = base64.b64decode(envelope["signature"])
    pub_pem    = base64.b64decode(envelope["public_key"])

    # Reconstruct signing input
    aad = f"{sender}|{timestamp}".encode()
    signing_input = (
        base64.b64decode(encrypted["nonce"]) +
        base64.b64decode(encrypted["ciphertext"]) +
        aad
    )

    # Verify signature
    try:
        public_key = serialization.load_pem_public_key(pub_pem)
        sig_valid  = IdentityKey.verify(public_key, signing_input, signature)
    except Exception:
        sig_valid = False

    # Decrypt (will raise if GCM tag fails → tampered ciphertext)
    plaintext = decrypt_message(enc_key, encrypted, associated_data=aad)

    return plaintext, sig_valid


# ──────────────────────────────────────────────────────────────────────────────
# 6. UTILITIES
# ──────────────────────────────────────────────────────────────────────────────

def generate_salt() -> bytes:
    """Cryptographically random 32-byte salt."""
    return os.urandom(32)

def bytes_to_b64(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64_to_bytes(s: str) -> bytes:
    return base64.b64decode(s)

def compute_hmac(key: bytes, data: bytes) -> str:
    """Additional HMAC-SHA256 for explicit MAC verification (defence-in-depth)."""
    mac = hmac.new(key, data, hashlib.sha256).digest()
    return base64.b64encode(mac).decode()

def verify_hmac(key: bytes, data: bytes, mac_b64: str) -> bool:
    expected = base64.b64decode(mac_b64)
    actual   = hmac.new(key, data, hashlib.sha256).digest()
    return hmac.compare_digest(expected, actual)   # constant-time comparison
