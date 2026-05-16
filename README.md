# 🔒 Secure Chat Application — E2E Encrypted

A production-grade secure chat system implementing the same cryptographic
principles used by Signal and WhatsApp.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────┐
│                     CLIENT A (Alice)                     │
│  IdentityKey (ECDSA P-256)  +  EphemeralKey (X25519)    │
└────────────────────────┬─────────────────────────────────┘
                         │  WebSocket (JSON frames)
                         │  Server only sees: encrypted blobs
                         │
┌────────────────────────▼─────────────────────────────────┐
│              FastAPI SERVER (blind relay)                 │
│  - User registration/login (bcrypt + JWT)                │
│  - Routes key exchange messages                          │
│  - Routes encrypted chat messages (never decrypts)       │
│  - Offline message queue                                 │
└────────────────────────┬─────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────┐
│                     CLIENT B (Bob)                       │
│  IdentityKey (ECDSA P-256)  +  EphemeralKey (X25519)    │
└──────────────────────────────────────────────────────────┘
```

---

## Cryptographic Protocol

### 1. Identity Keys (ECDSA P-256)
- Generated once per user at registration
- Used **only for signing** — never encryption
- Fingerprint = SHA-256(public_key) shown as hex pairs
- Users compare fingerprints out-of-band to defeat MITM

### 2. Key Exchange (X25519 ECDH + HKDF)
```
Alice                          Server                    Bob
  |                              |                        |
  |-- KeyExchangeInit ---------> |                        |
  |   (ephemeral_pub, salt,      |                        |
  |    ECDSA signature)          |-- forward -----------> |
  |                              |                        |
  |                              | <-- KeyExchangeResp -- |
  | <-- forward ----------------|    (ephemeral_pub, salt,|
  |                              |     ECDSA signature)   |
  |                              |                        |
  [Both compute X25519 DH → same shared secret]
  [Both run HKDF → enc_key (32B) + mac_key (32B)]
```

### 3. Message Encryption (AES-256-GCM)
```python
# Each message gets a fresh 96-bit nonce
nonce      = os.urandom(12)
aad        = f"{sender}|{timestamp}".encode()   # not encrypted but authenticated
ciphertext = AES-GCM(enc_key, nonce, plaintext, aad)

# Sign ciphertext with ECDSA identity key
signing_input = nonce + ciphertext + aad
signature     = ECDSA_P256_SHA256(identity_private, signing_input)

# Additional HMAC for defence-in-depth
mac = HMAC_SHA256(mac_key, nonce + ciphertext)
```

### 4. Security Properties

| Property | Mechanism |
|---|---|
| Confidentiality | AES-256-GCM |
| Integrity | GCM 128-bit auth tag |
| Authenticity | ECDSA P-256 signature |
| **Perfect Forward Secrecy** | Fresh X25519 ephemeral keys per session |
| **MITM Resistance** | Fingerprint comparison out-of-band |
| Replay Protection | Sender+timestamp bound to ciphertext via AAD |
| Defence-in-Depth | HMAC-SHA256 over encrypted payload |

---

## Project Structure

```
secure_chat/
├── shared/
│   ├── crypto.py       ← All cryptographic primitives (well-commented)
│   └── models.py       ← Pydantic schemas for all messages
├── server/
│   └── server.py       ← FastAPI + WebSocket server
├── client/
│   └── client.py       ← Terminal chat client
├── tests/
│   └── test_crypto.py  ← Full test suite (pytest)
├── demo.py             ← Protocol demo (no server needed)
└── requirements.txt
```

---

## Installation & Running

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the demo (no server needed)
```bash
python demo.py
```

### 3. Start the server
```bash
uvicorn server.server:app --host 0.0.0.0 --port 8765
```

### 4. Start a client (in a new terminal)
```bash
python -m client.client
```
Open another terminal and run a second client to chat between them.

### 5. Run the tests
```bash
python -m pytest tests/ -v
```

---

## How It Compares to Signal Protocol

| Feature | Signal Protocol | This Implementation |
|---|---|---|
| Identity keys | Ed25519 | ECDSA P-256 |
| Key exchange | X3DH (Triple DH) | X25519 ECDH |
| Encryption | AES-256-CBC + HMAC | AES-256-GCM |
| Forward secrecy | Double Ratchet | Per-session ephemeral keys |
| Signatures | Ed25519 | ECDSA P-256 |
| Key derivation | HKDF | HKDF-SHA256 |

This implementation uses AES-GCM (AEAD) which is actually more modern
than Signal's original AES-CBC + separate HMAC approach.

For full Signal-level forward secrecy, the next step would be implementing
the **Double Ratchet Algorithm** (ratcheting keys after every message).

---

## Security Notes

- **Never reuse a nonce** with the same key — AES-GCM is catastrophically
  broken if nonces are reused. This code uses `os.urandom(12)` per message.
- In production: store identity keys encrypted on disk, not in memory.
- The server's `JWT_SECRET` must be a cryptographically random 32+ byte value.
- TLS should be used for the WebSocket connection in production.
