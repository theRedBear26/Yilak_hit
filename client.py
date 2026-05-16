"""
client/client.py
================
Secure Chat Client — Terminal-based, asyncio

Full cryptographic protocol:
  1. Register / Login  (REST → get JWT)
  2. Connect WebSocket (JWT in URL)
  3. Start chat with peer:
       a. Generate ephemeral X25519 key pair
       b. Send KeyExchangeInit (signed with identity key)
       c. Receive peer's ephemeral public key
       d. ECDH → shared secret
       e. HKDF → enc_key + mac_key
  4. All messages encrypted with AES-256-GCM + ECDSA signature
  5. Fingerprint comparison for MITM resistance

Usage:
    python -m client.client
"""

import asyncio
import json
import base64
import sys
import os
import hashlib
import getpass
from datetime import datetime, timezone
from typing import Optional, Dict

import websockets
import aiohttp
from colorama import Fore, Style, init as colorama_init

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.crypto import (
    IdentityKey, EphemeralKey,
    derive_session_keys,
    create_signed_message, verify_and_decrypt,
    generate_salt, bytes_to_b64, b64_to_bytes,
    compute_hmac, verify_hmac
)

colorama_init()

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

SERVER_HTTP = os.environ.get("SERVER_HTTP", "http://localhost:8765")
SERVER_WS   = os.environ.get("SERVER_WS",   "ws://localhost:8765")


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def c(text: str, color: str) -> str:
    return f"{color}{text}{Style.RESET_ALL}"

def info(msg: str):   print(c(f"[*] {msg}", Fore.CYAN))
def ok(msg: str):     print(c(f"[✓] {msg}", Fore.GREEN))
def warn(msg: str):   print(c(f"[!] {msg}", Fore.YELLOW))
def err(msg: str):    print(c(f"[✗] {msg}", Fore.RED))
def chat_in(sender: str, msg: str, verified: bool):
    badge = c("✓SIG", Fore.GREEN) if verified else c("!SIG", Fore.RED)
    print(f"\n  {c(sender, Fore.MAGENTA)} [{badge}]: {msg}")

def chat_out(msg: str):
    print(c(f"  You: {msg}", Fore.WHITE))

def print_banner():
    banner = r"""
  ╔═══════════════════════════════════════════════════╗
  ║        🔒 SECURE CHAT — E2E ENCRYPTED             ║
  ║   ECDH + AES-256-GCM + ECDSA + PFS               ║
  ╚═══════════════════════════════════════════════════╝
    """
    print(c(banner, Fore.CYAN))


# ──────────────────────────────────────────────────────────────────────────────
# ChatSession — manages crypto state for one peer conversation
# ──────────────────────────────────────────────────────────────────────────────

class ChatSession:
    """
    Holds all cryptographic state for a session with one peer.

    Lifecycle:
      PENDING   → waiting for key exchange to complete
      ACTIVE    → keys derived, messages can flow
    """

    def __init__(self, peer_username: str):
        self.peer          = peer_username
        self.ephemeral     = EphemeralKey()       # fresh X25519 key pair
        self.salt          = generate_salt()
        self.enc_key: Optional[bytes] = None
        self.mac_key: Optional[bytes] = None
        self.ready         = False
        self.peer_identity_pub_pem: Optional[bytes] = None  # for fingerprint

    def complete_handshake(self, peer_ephemeral_b64: str, peer_salt_b64: str):
        """
        Derive session keys after receiving peer's ephemeral public.

        shared_secret = X25519(our_private, peer_public)
        (enc_key, mac_key) = HKDF(shared_secret, salt=XOR(salt_a, salt_b))
        """
        peer_pub_bytes = b64_to_bytes(peer_ephemeral_b64)
        peer_salt      = b64_to_bytes(peer_salt_b64)

        # Combine salts: XOR ensures same result regardless of who initiates
        combined_salt = bytes(a ^ b for a, b in zip(self.salt, peer_salt))

        shared_secret = self.ephemeral.exchange(peer_pub_bytes)
        self.enc_key, self.mac_key = derive_session_keys(shared_secret, combined_salt)
        self.ready = True

    def peer_fingerprint(self) -> Optional[str]:
        """SHA-256 of peer's identity public key, formatted as hex pairs."""
        if not self.peer_identity_pub_pem:
            return None
        from cryptography.hazmat.primitives import serialization as sl
        pub = sl.load_pem_public_key(self.peer_identity_pub_pem)
        raw = pub.public_bytes(
            encoding=sl.Encoding.X962,
            format=sl.PublicFormat.UncompressedPoint
        )
        digest = hashlib.sha256(raw).digest()
        return ':'.join(f'{b:02X}' for b in digest)


# ──────────────────────────────────────────────────────────────────────────────
# SecureChatClient
# ──────────────────────────────────────────────────────────────────────────────

class SecureChatClient:

    def __init__(self):
        self.username:     Optional[str]  = None
        self.token:        Optional[str]  = None
        self.identity:     Optional[IdentityKey] = None
        self.sessions:     Dict[str, ChatSession] = {}
        self.active_peer:  Optional[str]  = None
        self.ws:           Optional[websockets.WebSocketClientProtocol] = None
        self._recv_task:   Optional[asyncio.Task] = None

    # ── REST ──────────────────────────────────────────────────────────────

    async def register(self, username: str, password: str) -> bool:
        self.identity = IdentityKey()
        payload = {
            "username": username,
            "password": password,
            "identity_public_key": base64.b64encode(
                self.identity.public_bytes()
            ).decode()
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{SERVER_HTTP}/register", json=payload) as r:
                data = await r.json()
                if data.get("success"):
                    ok(f"Registered as {username}")
                    self.username = username
                    return True
                else:
                    err(f"Registration failed: {data.get('message', r.status)}")
                    return False

    async def login(self, username: str, password: str) -> bool:
        """Login and retrieve JWT. Regenerates identity key (demo only)."""
        if not self.identity:
            self.identity = IdentityKey()   # In production: load from disk

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{SERVER_HTTP}/login",
                json={"username": username, "password": password}
            ) as r:
                data = await r.json()
                if data.get("success"):
                    self.token    = data["token"]
                    self.username = username
                    ok(f"Logged in as {username}")
                    info(f"Your fingerprint: {self.identity.fingerprint()}")
                    return True
                else:
                    err(f"Login failed: {data.get('message', r.status)}")
                    return False

    # ── WebSocket ─────────────────────────────────────────────────────────

    async def connect(self):
        uri = f"{SERVER_WS}/ws/{self.token}"
        self.ws = await websockets.connect(uri)
        ok("WebSocket connected — end-to-end encryption active")
        self._recv_task = asyncio.create_task(self._receive_loop())

    async def disconnect(self):
        if self._recv_task:
            self._recv_task.cancel()
        if self.ws:
            await self.ws.close()

    async def _send(self, data: dict):
        await self.ws.send(json.dumps(data))

    # ── Key Exchange ──────────────────────────────────────────────────────

    async def initiate_key_exchange(self, peer: str):
        """
        Step 1 of handshake: send our ephemeral public + salt to peer.
        Sign the payload so peer can verify our identity.
        """
        session = ChatSession(peer)
        self.sessions[peer] = session

        # Sign: ECDSA over (ephemeral_pub_bytes + salt)
        signing_input = session.ephemeral.public_bytes() + session.salt
        signature     = self.identity.sign(signing_input)

        await self._send({
            "type":              "key_exchange_init",
            "from_user":         self.username,
            "to_user":           peer,
            "ephemeral_public":  session.ephemeral.public_b64(),
            "salt":              bytes_to_b64(session.salt),
            "identity_public_key": base64.b64encode(
                self.identity.public_bytes()
            ).decode(),
            "signature": bytes_to_b64(signature)
        })
        info(f"Key exchange initiated with {peer}")

    async def respond_key_exchange(self, msg: dict):
        """
        Step 2 of handshake: receive initiator's ephemeral key,
        create our own, derive shared keys, send our ephemeral back.
        """
        peer         = msg["from_user"]
        session      = ChatSession(peer)
        self.sessions[peer] = session

        # Store peer's identity key for fingerprint verification
        session.peer_identity_pub_pem = base64.b64decode(
            msg["identity_public_key"]
        )

        # Verify initiator's signature
        signing_input = (
            b64_to_bytes(msg["ephemeral_public"]) +
            b64_to_bytes(msg["salt"])
        )
        from cryptography.hazmat.primitives import serialization as sl
        peer_pub = sl.load_pem_public_key(session.peer_identity_pub_pem)
        sig_ok   = IdentityKey.verify(
            peer_pub, signing_input, b64_to_bytes(msg["signature"])
        )

        if not sig_ok:
            err(f"BAD SIGNATURE from {peer} during key exchange! Aborting.")
            del self.sessions[peer]
            return

        # Derive our keys
        session.complete_handshake(msg["ephemeral_public"], msg["salt"])

        # Send our ephemeral public back
        my_signing_input = session.ephemeral.public_bytes() + session.salt
        my_signature     = self.identity.sign(my_signing_input)

        await self._send({
            "type":              "key_exchange_response",
            "from_user":         self.username,
            "to_user":           peer,
            "ephemeral_public":  session.ephemeral.public_b64(),
            "salt":              bytes_to_b64(session.salt),
            "identity_public_key": base64.b64encode(
                self.identity.public_bytes()
            ).decode(),
            "signature": bytes_to_b64(my_signature)
        })

        fp = session.peer_fingerprint()
        ok(f"Secure session established with {peer}")
        warn(f"Peer fingerprint: {fp}")
        warn("Verify this fingerprint out-of-band (e.g., phone call) to prevent MITM!")

    async def finalize_key_exchange(self, msg: dict):
        """
        Initiator receives responder's ephemeral public and finalises keys.
        """
        peer    = msg["from_user"]
        session = self.sessions.get(peer)
        if not session:
            return

        session.peer_identity_pub_pem = base64.b64decode(
            msg["identity_public_key"]
        )

        # Verify responder's signature
        signing_input = (
            b64_to_bytes(msg["ephemeral_public"]) +
            b64_to_bytes(msg["salt"])
        )
        from cryptography.hazmat.primitives import serialization as sl
        peer_pub = sl.load_pem_public_key(session.peer_identity_pub_pem)
        sig_ok   = IdentityKey.verify(
            peer_pub, signing_input, b64_to_bytes(msg["signature"])
        )

        if not sig_ok:
            err(f"BAD SIGNATURE from {peer} during KX response!")
            del self.sessions[peer]
            return

        session.complete_handshake(msg["ephemeral_public"], msg["salt"])

        fp = session.peer_fingerprint()
        ok(f"Secure session established with {peer} (PFS active)")
        warn(f"Peer fingerprint: {fp}")
        warn("Verify this fingerprint out-of-band to defeat MITM attacks!")

    # ── Send / Receive ────────────────────────────────────────────────────

    async def send_message(self, peer: str, plaintext: str):
        session = self.sessions.get(peer)
        if not session or not session.ready:
            err("No active session with that user. Use /chat <user> first.")
            return

        timestamp = datetime.now(timezone.utc).isoformat()

        # Build signed + encrypted envelope
        envelope = create_signed_message(
            plaintext, session.enc_key,
            self.identity, self.username, timestamp
        )

        # Additional HMAC over the whole encrypted payload (defence-in-depth)
        mac_input = (
            base64.b64decode(envelope["encrypted"]["nonce"]) +
            base64.b64decode(envelope["encrypted"]["ciphertext"])
        )
        mac = compute_hmac(session.mac_key, mac_input)

        await self._send({
            "type":      "chat",
            "to_user":   peer,
            "encrypted": envelope["encrypted"],
            "signature": envelope["signature"],
            "sender":    self.username,
            "timestamp": timestamp,
            "public_key": envelope["public_key"],
            "mac":       mac
        })

    def _handle_incoming_message(self, msg: dict):
        sender  = msg.get("from_user") or msg.get("sender")
        session = self.sessions.get(sender)

        if not session or not session.ready:
            warn(f"Received message from {sender} but no active session.")
            return

        # Verify HMAC
        mac_input = (
            base64.b64decode(msg["encrypted"]["nonce"]) +
            base64.b64decode(msg["encrypted"]["ciphertext"])
        )
        if msg.get("mac"):
            mac_ok = verify_hmac(session.mac_key, mac_input, msg["mac"])
            if not mac_ok:
                err(f"HMAC VERIFICATION FAILED for message from {sender}!")
                return
        try:
            plaintext, sig_valid = verify_and_decrypt(
                {
                    "encrypted":  msg["encrypted"],
                    "signature":  msg["signature"],
                    "sender":     sender,
                    "timestamp":  msg.get("timestamp", ""),
                    "public_key": msg["public_key"]
                },
                session.enc_key
            )
            chat_in(sender, plaintext, sig_valid)
            if not sig_valid:
                warn("Signature verification failed — message authenticity unconfirmed!")
        except ValueError as e:
            err(f"Decryption error: {e}")

    # ── Receive loop ──────────────────────────────────────────────────────

    async def _receive_loop(self):
        """Background task: handle all incoming WebSocket messages."""
        try:
            async for raw in self.ws:
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                t = msg.get("type", "")

                if t == "key_exchange_init":
                    await self.respond_key_exchange(msg)
                elif t == "key_exchange_response":
                    await self.finalize_key_exchange(msg)
                elif t == "message":
                    self._handle_incoming_message(msg)
                elif t == "user_list":
                    online = msg.get("users", [])
                    print(c(f"\n  [Online: {', '.join(online)}]", Fore.BLUE))
                elif t == "status":
                    event   = msg.get("event", "")
                    message = msg.get("message", "")
                    color   = Fore.GREEN if event == "info" else Fore.YELLOW
                    print(c(f"\n  [Server] {message}", color))
        except websockets.ConnectionClosed:
            warn("Connection closed by server.")
        except asyncio.CancelledError:
            pass


# ──────────────────────────────────────────────────────────────────────────────
# Main interactive loop
# ──────────────────────────────────────────────────────────────────────────────

async def main():
    print_banner()
    client = SecureChatClient()

    # ── Auth ──────────────────────────────────────────────────────────────
    print(c("\nCommands: register | login\n", Fore.CYAN))
    action = input("  > ").strip().lower()

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    if action == "register":
        ok_auth = await client.register(username, password)
        if not ok_auth:
            return
        ok_auth = await client.login(username, password)
    else:
        ok_auth = await client.login(username, password)

    if not ok_auth:
        return

    # ── Connect WebSocket ─────────────────────────────────────────────────
    await client.connect()
    await asyncio.sleep(0.5)   # let welcome message arrive

    # ── Command loop ──────────────────────────────────────────────────────
    help_text = c("""
  Commands:
    /chat <user>      — Open encrypted session with user
    /users            — Show online users
    /fingerprint      — Show your own fingerprint
    /fp <user>        — Show peer fingerprint (verify MITM resistance)
    /quit             — Exit
    (anything else)   — Send as encrypted message to active peer
    """, Fore.CYAN)
    print(help_text)

    loop = asyncio.get_event_loop()

    try:
        while True:
            # Read input in executor so we don't block the event loop
            line = await loop.run_in_executor(None, lambda: input("  > ").strip())

            if not line:
                continue

            if line.startswith("/chat "):
                peer = line[6:].strip()
                if peer == client.username:
                    err("Cannot chat with yourself.")
                    continue
                client.active_peer = peer
                await client.initiate_key_exchange(peer)
                # Give the handshake a moment to complete
                await asyncio.sleep(0.8)

            elif line == "/users":
                await client._send({"type": "get_users"})

            elif line == "/fingerprint":
                ok(f"Your fingerprint: {client.identity.fingerprint()}")

            elif line.startswith("/fp "):
                peer = line[4:].strip()
                session = client.sessions.get(peer)
                if session:
                    fp = session.peer_fingerprint()
                    if fp:
                        ok(f"{peer}'s fingerprint: {fp}")
                        warn("Compare this with them over a secure channel (e.g. phone call).")
                    else:
                        warn("No identity key on record for that user yet.")
                else:
                    warn("No session with that user.")

            elif line in ("/quit", "/exit"):
                break

            elif line.startswith("/"):
                warn("Unknown command.")

            else:
                if not client.active_peer:
                    warn("No active peer. Use /chat <user> first.")
                else:
                    await client.send_message(client.active_peer, line)

    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        await client.disconnect()
        info("Disconnected. Goodbye.")


if __name__ == "__main__":
    asyncio.run(main())
