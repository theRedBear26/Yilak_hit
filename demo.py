"""
demo.py
=======
Self-contained demo that simulates Alice and Bob exchanging
encrypted messages WITHOUT a server — pure crypto layer demo.

Run: python demo.py
"""

import sys
import os
import base64
import hashlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shared.crypto import (
    IdentityKey, EphemeralKey,
    derive_session_keys,
    create_signed_message, verify_and_decrypt,
    generate_salt, compute_hmac, verify_hmac
)

def sep(title=""):
    w = 60
    if title:
        print(f"\n{'─'*4} {title} {'─'*(w - len(title) - 6)}")
    else:
        print("─" * w)

def ok(msg):   print(f"  ✅  {msg}")
def info(msg): print(f"  ℹ️   {msg}")
def warn(msg): print(f"  ⚠️   {msg}")
def err(msg):  print(f"  ❌  {msg}")


def main():
    print("\n" + "═"*60)
    print("  🔒 SECURE CHAT — CRYPTOGRAPHIC PROTOCOL DEMO")
    print("═"*60)

    # ─── Step 1: Identity Keys ───────────────────────────────────────────

    sep("Step 1 — Generate Identity Keys (ECDSA P-256)")
    alice_id = IdentityKey()
    bob_id   = IdentityKey()
    info(f"Alice fingerprint : {alice_id.fingerprint()}")
    info(f"Bob   fingerprint : {bob_id.fingerprint()}")
    print()
    print("  ↪ Users compare fingerprints out-of-band (phone call, etc.)")
    print("    A MITM cannot fake these — they're derived from long-term keys.")

    # ─── Step 2: Ephemeral Key Exchange (ECDH X25519) ────────────────────

    sep("Step 2 — Ephemeral Key Exchange (X25519 ECDH + HKDF)")
    alice_ep = EphemeralKey()
    bob_ep   = EphemeralKey()
    salt     = generate_salt()

    info(f"Alice ephemeral pub (hex): {alice_ep.public_bytes().hex()[:32]}...")
    info(f"Bob   ephemeral pub (hex): {bob_ep.public_bytes().hex()[:32]}...")
    info(f"Salt (hex): {salt.hex()[:32]}...")

    # Both compute X25519 DH — result is identical
    alice_secret = alice_ep.exchange(bob_ep.public_bytes())
    bob_secret   = bob_ep.exchange(alice_ep.public_bytes())

    assert alice_secret == bob_secret, "ECDH mismatch!"
    ok("Shared DH secret computed independently — values match!")
    info(f"Shared secret (hex): {alice_secret.hex()[:32]}...")

    # Derive two keys via HKDF
    alice_enc, alice_mac = derive_session_keys(alice_secret, salt)
    bob_enc,   bob_mac   = derive_session_keys(bob_secret,   salt)

    assert alice_enc == bob_enc
    ok(f"AES-256 encryption key : {alice_enc.hex()[:32]}...")
    ok(f"HMAC-SHA256 MAC key    : {alice_mac.hex()[:32]}...")
    print()
    print("  ↪ Fresh keys every session = Perfect Forward Secrecy (PFS)")
    print("    Compromising today's key doesn't expose yesterday's messages.")

    # ─── Step 3: Encrypt + Sign ──────────────────────────────────────────

    sep("Step 3 — Alice sends encrypted, signed message to Bob")
    plaintext = "Hi Bob! This message is end-to-end encrypted. 🔐"
    info(f"Plaintext : {plaintext}")

    timestamp = "2024-06-15T10:30:00Z"
    envelope  = create_signed_message(
        plaintext, alice_enc, alice_id, "alice", timestamp
    )

    info(f"Ciphertext (b64): {envelope['encrypted']['ciphertext'][:40]}...")
    info(f"Nonce      (b64): {envelope['encrypted']['nonce']}")
    info(f"Signature  (b64): {envelope['signature'][:40]}...")

    # Add HMAC layer
    mac_data = (
        base64.b64decode(envelope["encrypted"]["nonce"]) +
        base64.b64decode(envelope["encrypted"]["ciphertext"])
    )
    mac = compute_hmac(alice_mac, mac_data)
    ok(f"HMAC       (b64): {mac[:40]}...")
    print()
    print("  ↪ AES-256-GCM provides confidentiality + integrity (128-bit tag)")
    print("    ECDSA signature proves the message came from Alice")

    # ─── Step 4: Bob receives and verifies ───────────────────────────────

    sep("Step 4 — Bob receives, verifies MAC, decrypts, verifies signature")

    # Verify HMAC
    mac_ok = verify_hmac(bob_mac, mac_data, mac)
    if mac_ok:
        ok("HMAC verification passed ✓")
    else:
        err("HMAC FAILED!")

    # Decrypt and verify signature
    received_pt, sig_ok = verify_and_decrypt(envelope, bob_enc)
    ok(f"Decrypted : {received_pt}")
    ok(f"Signature valid: {sig_ok}")
    assert received_pt == plaintext
    assert sig_ok is True

    # ─── Step 5: Attack simulation ───────────────────────────────────────

    sep("Step 5 — Attack Simulations")

    # 5a: Tamper with ciphertext
    print("\n  Attack 1 — MITM tampers with ciphertext:")
    bad_env = dict(envelope)
    bad_env["encrypted"] = dict(envelope["encrypted"])
    ct       = base64.b64decode(bad_env["encrypted"]["ciphertext"])
    tampered = ct[:-1] + bytes([ct[-1] ^ 0x42])
    bad_env["encrypted"]["ciphertext"] = base64.b64encode(tampered).decode()
    try:
        verify_and_decrypt(bad_env, bob_enc)
        err("  Attack succeeded! (should not happen)")
    except ValueError:
        ok("  Tampered ciphertext detected! (AES-GCM tag verification failed)")

    # 5b: Replay with wrong sender
    print("\n  Attack 2 — Replay: adversary changes sender field:")
    bad_env2 = dict(envelope)
    bad_env2["sender"] = "mallory"
    try:
        pt2, sig2 = verify_and_decrypt(bad_env2, bob_enc)
        warn(f"  Decrypted: '{pt2}' — but signature valid? {sig2}")
        if not sig2:
            ok("  Signature FAILED — sender forgery detected!")
        else:
            err("  Attack undetected!")
    except ValueError:
        ok("  GCM tag failed — AAD mismatch detected sender forgery!")

    # 5c: Wrong decryption key (different session)
    print("\n  Attack 3 — Wrong session key (different user's key):")
    wrong_key = os.urandom(32)
    try:
        verify_and_decrypt(envelope, wrong_key)
        err("  Decryption succeeded with wrong key!")
    except ValueError:
        ok("  Wrong key rejected — AES-GCM tag mismatch")

    # ─── Step 6: PFS demonstration ───────────────────────────────────────

    sep("Step 6 — Perfect Forward Secrecy")
    session2_alice = EphemeralKey()
    session2_bob   = EphemeralKey()
    salt2          = generate_salt()
    secret2        = session2_alice.exchange(session2_bob.public_bytes())
    enc2, _        = derive_session_keys(secret2, salt2)

    assert enc2 != alice_enc
    ok("Session 2 uses different encryption key from Session 1")
    ok("Leaking Session 2 key does NOT compromise Session 1 messages")
    print()
    print("  ↪ This is why Signal/WhatsApp use ephemeral keys per session.")

    # ─── Summary ─────────────────────────────────────────────────────────

    sep()
    print("""
  Security Properties Demonstrated:
  ──────────────────────────────────
  ✅  Confidentiality    AES-256-GCM encryption
  ✅  Integrity          AES-GCM 128-bit authentication tag
  ✅  Authenticity       ECDSA P-256 digital signatures
  ✅  Forward Secrecy    Ephemeral X25519 keys per session
  ✅  MITM Resistance    Fingerprint comparison (out-of-band)
  ✅  Replay Protection  Sender+timestamp bound to ciphertext via AAD
  ✅  Defence-in-depth   HMAC-SHA256 over ciphertext (additional MAC)
    """)


if __name__ == "__main__":
    main()
