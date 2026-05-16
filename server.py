"""
server/server.py
================
Secure Chat Server — FastAPI + WebSockets

Security model:
  - The server is a BLIND RELAY for encrypted messages.
    It never sees plaintext. It stores only:
      • Hashed passwords (bcrypt)
      • Identity public keys (for fingerprint display)
      • Offline message queue (still encrypted)

  - Key exchange handshakes are forwarded verbatim so clients
    can establish shared secrets without server involvement.

  - JWT tokens for session authentication (HS256, short-lived).

  - All WebSocket frames are JSON; the server validates structure
    but cannot read the AES-GCM encrypted content.

Run:
    uvicorn server.server:app --host 0.0.0.0 --port 8765 --reload
"""

import json
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import jwt
from fastapi import (
    FastAPI, WebSocket, WebSocketDisconnect,
    HTTPException, Depends, status
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from pydantic import ValidationError

# Add parent to path so shared/ is importable when running from project root
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.models import (
    RegisterRequest, LoginRequest, AuthResponse,
    KeyExchangeInit, KeyExchangeResponse,
    ChatMessage, ChatDelivery,
    UserList, StatusMessage
)

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

JWT_SECRET      = os.environ.get("JWT_SECRET", "CHANGE_THIS_IN_PRODUCTION_32BYTES!")
JWT_ALGORITHM   = "HS256"
JWT_EXPIRE_MINS = 60 * 8   # 8-hour tokens

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s"
)
log = logging.getLogger("secure-chat-server")

# ──────────────────────────────────────────────────────────────────────────────
# In-memory stores  (replace with DB in production)
# ──────────────────────────────────────────────────────────────────────────────

# { username: { "password_hash": str, "identity_public_key": str } }
USERS: Dict[str, dict] = {}

# { username: WebSocket }  — active connections
CONNECTIONS: Dict[str, WebSocket] = {}

# { username: [ message_dict ] }  — offline message queue
OFFLINE_QUEUE: Dict[str, List[dict]] = {}

# ──────────────────────────────────────────────────────────────────────────────
# Auth helpers
# ──────────────────────────────────────────────────────────────────────────────

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer  = HTTPBearer()


def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)


def create_token(username: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINS)
    payload = {"sub": username, "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> Optional[str]:
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return data.get("sub")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> str:
    return decode_token(creds.credentials)


# ──────────────────────────────────────────────────────────────────────────────
# FastAPI app
# ──────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Secure Chat Server",
    description="E2E encrypted chat with ECDH + AES-GCM + ECDSA",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────────────────────────────────────
# REST endpoints
# ──────────────────────────────────────────────────────────────────────────────

@app.post("/register", response_model=AuthResponse)
async def register(req: RegisterRequest):
    """
    Register a new user.
    Stores bcrypt-hashed password and ECDSA public key.
    The public key is used for fingerprint verification by other users.
    """
    if req.username in USERS:
        raise HTTPException(400, "Username already taken")
    USERS[req.username] = {
        "password_hash":     hash_password(req.password),
        "identity_public_key": req.identity_public_key
    }
    log.info(f"Registered user: {req.username}")
    return AuthResponse(success=True, message="Registered successfully")


@app.post("/login", response_model=AuthResponse)
async def login(req: LoginRequest):
    """Authenticate and return a JWT."""
    user = USERS.get(req.username)
    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(401, "Invalid credentials")
    token = create_token(req.username)
    log.info(f"Login: {req.username}")
    return AuthResponse(success=True, token=token)


@app.get("/users")
async def list_users(username: str = Depends(get_current_user)):
    """Return list of registered users (auth required)."""
    return {"users": list(USERS.keys())}


@app.get("/fingerprint/{username}")
async def get_fingerprint(username: str, _: str = Depends(get_current_user)):
    """
    Return a user's identity public key.
    Clients compute SHA-256(public_key) and display it as a fingerprint.
    Out-of-band comparison defeats MITM attacks.
    """
    user = USERS.get(username)
    if not user:
        raise HTTPException(404, "User not found")
    return {
        "username": username,
        "identity_public_key": user["identity_public_key"]
    }


@app.get("/health")
async def health():
    return {"status": "ok", "connected_users": list(CONNECTIONS.keys())}


# ──────────────────────────────────────────────────────────────────────────────
# WebSocket endpoint
# ──────────────────────────────────────────────────────────────────────────────

async def ws_send(ws: WebSocket, data: dict):
    """Helper: send JSON frame, swallow closed-connection errors."""
    try:
        await ws.send_text(json.dumps(data))
    except Exception:
        pass


async def broadcast_user_list():
    """Notify all connected users of the current online roster."""
    online = list(CONNECTIONS.keys())
    msg    = {"type": "user_list", "users": online}
    for ws in list(CONNECTIONS.values()):
        await ws_send(ws, msg)


@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    """
    Main WebSocket handler.

    Authentication: JWT passed in URL path (avoids header limitations
    of browser WebSocket API).

    Message routing:
      key_exchange_init/response  → forwarded to target user
      chat                        → forwarded to target user (or queued)
      get_users                   → respond with online list
    """
    # ── Authenticate ───────────────────────────────────────────────────────
    try:
        username = decode_token(token)
    except HTTPException:
        await websocket.close(code=4001, reason="Unauthorized")
        return

    await websocket.accept()
    CONNECTIONS[username] = websocket
    log.info(f"[WS] Connected: {username}")

    # Deliver any offline messages
    if username in OFFLINE_QUEUE:
        for queued_msg in OFFLINE_QUEUE.pop(username):
            await ws_send(websocket, queued_msg)

    # Announce presence
    await broadcast_user_list()
    await ws_send(websocket, {
        "type": "status",
        "event": "info",
        "message": f"Welcome, {username}! You are securely connected."
    })

    # ── Message loop ───────────────────────────────────────────────────────
    try:
        while True:
            raw = await websocket.receive_text()

            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                await ws_send(websocket, {
                    "type": "status", "event": "error",
                    "message": "Invalid JSON"
                })
                continue

            msg_type = data.get("type", "")

            # ── Key exchange init ─────────────────────────────────────────
            if msg_type == "key_exchange_init":
                to_user = data.get("to_user")
                log.info(f"[KX-INIT] {username} → {to_user}")

                # Validate sender field matches authenticated user
                data["from_user"] = username

                if to_user in CONNECTIONS:
                    await ws_send(CONNECTIONS[to_user], data)
                else:
                    await ws_send(websocket, {
                        "type": "status", "event": "error",
                        "message": f"{to_user} is offline"
                    })

            # ── Key exchange response ─────────────────────────────────────
            elif msg_type == "key_exchange_response":
                to_user = data.get("to_user")
                data["from_user"] = username
                log.info(f"[KX-RESP] {username} → {to_user}")

                if to_user in CONNECTIONS:
                    await ws_send(CONNECTIONS[to_user], data)

            # ── Encrypted chat message ────────────────────────────────────
            elif msg_type == "chat":
                to_user = data.get("to_user")
                data["sender"] = username   # enforce sender = authenticated user

                delivery = {
                    "type":      "message",
                    "from_user": username,
                    "encrypted": data.get("encrypted"),
                    "signature": data.get("signature"),
                    "sender":    username,
                    "timestamp": data.get("timestamp"),
                    "public_key": data.get("public_key"),
                    "mac":       data.get("mac"),
                }

                log.info(f"[MSG] {username} → {to_user}")

                if to_user in CONNECTIONS:
                    await ws_send(CONNECTIONS[to_user], delivery)
                else:
                    # Queue for offline delivery
                    OFFLINE_QUEUE.setdefault(to_user, []).append(delivery)
                    await ws_send(websocket, {
                        "type": "status", "event": "info",
                        "message": f"{to_user} is offline — message queued for delivery."
                    })

            # ── Online user list ──────────────────────────────────────────
            elif msg_type == "get_users":
                await ws_send(websocket, {
                    "type": "user_list",
                    "users": list(CONNECTIONS.keys())
                })

            # ── Unknown ───────────────────────────────────────────────────
            else:
                log.warning(f"Unknown message type: {msg_type} from {username}")

    except WebSocketDisconnect:
        pass
    finally:
        CONNECTIONS.pop(username, None)
        log.info(f"[WS] Disconnected: {username}")
        await broadcast_user_list()
