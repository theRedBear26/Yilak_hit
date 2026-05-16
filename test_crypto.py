"""
tests/test_crypto.py
====================
Unit tests for all cryptographic primitives.
Run: python -m pytest tests/ -v
"""

import pytest
import sys
import os
import base64

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.crypto import (
    IdentityKey, EphemeralKey,
    derive_session_keys,
    encrypt_message, decrypt_message,
    create_signed_message, verify_and_decrypt,
    generate_salt, compute_hmac, verify_hmac
)


class TestIdentityKey:

    def test_generate_key_pair(self):
        key = IdentityKey()
        assert key.public_bytes()
        assert key.private_bytes()

    def test_sign_and_verify(self):
        key  = IdentityKey()
        data = b"Hello, World!"
        sig  = key.sign(data)
        pub  = IdentityKey.public_from_pem(key.public_bytes())
        assert IdentityKey.verify(pub, data, sig) is True

    def test_tampered_data_fails(self):
        key  = IdentityKey()
        data = b"Original message"
        sig  = key.sign(data)
        pub  = IdentityKey.public_from_pem(key.public_bytes())
        assert IdentityKey.verify(pub, b"Tampered!", sig) is False

    def test_wrong_key_fails(self):
        key1 = IdentityKey()
        key2 = IdentityKey()
        data = b"test"
        sig  = key1.sign(data)
        pub2 = IdentityKey.public_from_pem(key2.public_bytes())
        assert IdentityKey.verify(pub2, data, sig) is False

    def test_fingerprint_format(self):
        key = IdentityKey()
        fp  = key.fingerprint()
        parts = fp.split(':')
        assert len(parts) == 32            # SHA-256 = 32 bytes
        assert all(len(p) == 2 for p in parts)

    def test_fingerprint_deterministic(self):
        key = IdentityKey()
        assert key.fingerprint() == key.fingerprint()

    def test_different_keys_different_fingerprints(self):
        assert IdentityKey().fingerprint() != IdentityKey().fingerprint()


class TestEphemeralKey:

    def test_ecdh_shared_secret_matches(self):
        """Alice and Bob derive the same shared secret."""
        alice = EphemeralKey()
        bob   = EphemeralKey()

        alice_secret = alice.exchange(bob.public_bytes())
        bob_secret   = bob.exchange(alice.public_bytes())

        assert alice_secret == bob_secret

    def test_different_sessions_different_secrets(self):
        """Fresh keys → different secrets → Perfect Forward Secrecy."""
        a1, b1 = EphemeralKey(), EphemeralKey()
        a2, b2 = EphemeralKey(), EphemeralKey()

        s1 = a1.exchange(b1.public_bytes())
        s2 = a2.exchange(b2.public_bytes())

        assert s1 != s2

    def test_public_key_is_32_bytes(self):
        key = EphemeralKey()
        assert len(key.public_bytes()) == 32


class TestKeyDerivation:

    def test_derive_two_keys(self):
        secret = os.urandom(32)
        salt   = generate_salt()
        enc, mac = derive_session_keys(secret, salt)
        assert len(enc) == 32
        assert len(mac) == 32
        assert enc != mac

    def test_same_input_same_output(self):
        secret = os.urandom(32)
        salt   = generate_salt()
        enc1, mac1 = derive_session_keys(secret, salt)
        enc2, mac2 = derive_session_keys(secret, salt)
        assert enc1 == enc2
        assert mac1 == mac2

    def test_different_salts_different_keys(self):
        secret = os.urandom(32)
        enc1, _ = derive_session_keys(secret, generate_salt())
        enc2, _ = derive_session_keys(secret, generate_salt())
        assert enc1 != enc2


import os as _os

class TestAESGCM:

    def setup_method(self):
        self.key = _os.urandom(32)

    def test_encrypt_decrypt(self):
        pt      = "Hello, secure world!"
        payload = encrypt_message(self.key, pt)
        result  = decrypt_message(self.key, payload)
        assert result == pt

    def test_different_nonces_each_time(self):
        pt  = "same message"
        p1  = encrypt_message(self.key, pt)
        p2  = encrypt_message(self.key, pt)
        assert p1["nonce"] != p2["nonce"]
        assert p1["ciphertext"] != p2["ciphertext"]

    def test_wrong_key_fails(self):
        pt      = "secret"
        payload = encrypt_message(self.key, pt)
        with pytest.raises(ValueError):
            decrypt_message(_os.urandom(32), payload)

    def test_tampered_ciphertext_fails(self):
        pt      = "secret"
        payload = encrypt_message(self.key, pt)
        ct      = base64.b64decode(payload["ciphertext"])
        # Flip one byte
        tampered = ct[:-1] + bytes([ct[-1] ^ 0xFF])
        payload["ciphertext"] = base64.b64encode(tampered).decode()
        with pytest.raises(ValueError):
            decrypt_message(self.key, payload)

    def test_aad_binding(self):
        """Changing associated data causes decryption to fail."""
        pt  = "msg"
        aad = b"alice|2024-01-01"
        p   = encrypt_message(self.key, pt, associated_data=aad)
        with pytest.raises(ValueError):
            decrypt_message(self.key, p, associated_data=b"mallory|2024-01-01")

    def test_unicode_messages(self):
        pt = "Привет! 你好! مرحبا 🔒"
        assert decrypt_message(self.key, encrypt_message(self.key, pt)) == pt


class TestSignedMessages:

    def setup_method(self):
        self.key    = _os.urandom(32)
        self.identity = IdentityKey()

    def test_create_and_verify(self):
        envelope = create_signed_message(
            "hello", self.key, self.identity, "alice", "2024-01-01T00:00:00"
        )
        pt, sig_ok = verify_and_decrypt(envelope, self.key)
        assert pt == "hello"
        assert sig_ok is True

    def test_tampered_ciphertext_detected(self):
        envelope = create_signed_message(
            "hello", self.key, self.identity, "alice", "2024-01-01T00:00:00"
        )
        ct = base64.b64decode(envelope["encrypted"]["ciphertext"])
        envelope["encrypted"]["ciphertext"] = base64.b64encode(
            ct[:-1] + bytes([ct[-1] ^ 0xFF])
        ).decode()
        with pytest.raises(ValueError):
            verify_and_decrypt(envelope, self.key)

    def test_signature_detects_wrong_key(self):
        evil_key = IdentityKey()
        envelope = create_signed_message(
            "hello", self.key, self.identity, "alice", "2024-01-01T00:00:00"
        )
        # Replace public key with evil key's public key
        envelope["public_key"] = base64.b64encode(evil_key.public_bytes()).decode()
        pt, sig_ok = verify_and_decrypt(envelope, self.key)
        assert sig_ok is False

    def test_full_e2e_flow(self):
        """Simulate complete Alice ↔ Bob exchange."""
        # Generate identity keys
        alice_id = IdentityKey()
        bob_id   = IdentityKey()

        # Key exchange
        alice_ep = EphemeralKey()
        bob_ep   = EphemeralKey()
        salt     = generate_salt()

        alice_secret = alice_ep.exchange(bob_ep.public_bytes())
        bob_secret   = bob_ep.exchange(alice_ep.public_bytes())
        assert alice_secret == bob_secret

        alice_enc, alice_mac = derive_session_keys(alice_secret, salt)
        bob_enc,   bob_mac   = derive_session_keys(bob_secret,   salt)
        assert alice_enc == bob_enc

        # Alice sends to Bob
        ts  = "2024-01-01T12:00:00"
        env = create_signed_message("Hi Bob!", alice_enc, alice_id, "alice", ts)
        pt, ok = verify_and_decrypt(env, bob_enc)
        assert pt == "Hi Bob!"
        assert ok is True


class TestHMAC:

    def test_valid_mac(self):
        key  = _os.urandom(32)
        data = b"important data"
        mac  = compute_hmac(key, data)
        assert verify_hmac(key, data, mac)

    def test_tampered_data_fails(self):
        key  = _os.urandom(32)
        mac  = compute_hmac(key, b"data")
        assert not verify_hmac(key, b"different data", mac)

    def test_wrong_key_fails(self):
        data = b"data"
        mac  = compute_hmac(_os.urandom(32), data)
        assert not verify_hmac(_os.urandom(32), data, mac)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
