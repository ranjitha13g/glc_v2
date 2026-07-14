"""Out-of-band control plane: /v1/control/kill, /v1/control/pair,
/v1/control/pair/confirm, /v1/control/presence.

All endpoints require the installation token (Authorization: Bearer ...).
The kill endpoint binds 127.0.0.1 only; the host check is enforced here.
"""

from __future__ import annotations

import os
import signal
import threading
import time

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

from glc.config import get_or_create_install_token
from glc.security.pairing import CODE_TTL_SECONDS, get_pairing_store

router = APIRouter()

# C6: sliding-window lockout for pairing confirm — stops brute-force guessing
_CONFIRM_MAX_FAILURES = 5
_CONFIRM_WINDOW_S = 60
_confirm_failures: list[float] = []
_confirm_lock = threading.Lock()


def _confirm_check_and_record(failed: bool) -> None:
    now = time.time()
    with _confirm_lock:
        recent = [t for t in _confirm_failures if now - t < _CONFIRM_WINDOW_S]
        if len(recent) >= _CONFIRM_MAX_FAILURES:
            raise HTTPException(
                429,
                f"too many failed pairing attempts — wait {_CONFIRM_WINDOW_S}s",
            )
        if failed:
            recent.append(now)
        _confirm_failures.clear()
        _confirm_failures.extend(recent)


def _require_token(authorization: str | None) -> None:
    expected = get_or_create_install_token()
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token (Authorization: Bearer <install_token>)")
    presented = authorization.removeprefix("Bearer ").strip()
    if presented != expected:
        raise HTTPException(403, "install token mismatch")


class PairRequest(BaseModel):
    channel: str
    channel_user_id: str
    user_handle: str = ""
    trust_level: str = "user_paired"


class PairResponse(BaseModel):
    code: str
    expires_at: float
    ttl_seconds: int


class PairConfirmRequest(BaseModel):
    code: str


@router.post("/v1/control/pair", response_model=PairResponse)
async def pair(req: PairRequest, authorization: str | None = Header(default=None)):
    _require_token(authorization)
    if req.trust_level not in ("user_paired", "owner_paired"):
        raise HTTPException(400, f"trust_level must be user_paired or owner_paired, got {req.trust_level!r}")
    code, expires_at = get_pairing_store().issue_code(
        req.channel,
        req.channel_user_id,
        req.user_handle,
        requested_trust_level=req.trust_level,
    )
    return PairResponse(code=code, expires_at=expires_at, ttl_seconds=CODE_TTL_SECONDS)


@router.post("/v1/control/pair/confirm")
async def pair_confirm(req: PairConfirmRequest, authorization: str | None = Header(default=None)):
    _require_token(authorization)
    _confirm_check_and_record(failed=False)   # raises 429 if already locked out
    rec = get_pairing_store().confirm_code(req.code)
    if rec is None:
        _confirm_check_and_record(failed=True)  # record this failure
        raise HTTPException(404, "code unknown or expired")
    return {
        "channel": rec.channel,
        "channel_user_id": rec.channel_user_id,
        "user_handle": rec.user_handle,
        "trust_level": rec.trust_level,
        "paired_at": rec.paired_at,
    }


@router.get("/v1/control/presence")
async def presence(request: Request, authorization: str | None = Header(default=None)):
    _require_token(authorization)
    state = request.app.state
    started = getattr(state, "started_at", time.time())
    pairings = get_pairing_store().all_pairings()
    return {
        "channels": getattr(state, "registered_channels", []),
        "paired_users": [
            {
                "channel": p.channel,
                "channel_user_id": p.channel_user_id,
                "user_handle": p.user_handle,
                "trust_level": p.trust_level,
            }
            for p in pairings
        ],
        "uptime_s": int(time.time() - started),
    }


@router.post("/v1/control/kill")
async def kill(request: Request, authorization: str | None = Header(default=None)):
    _require_token(authorization)
    client_host = request.client.host if request.client else "unknown"
    if os.getenv("GLC_KILL_ALLOW_REMOTE") != "1" and client_host not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(
            403,
            f"kill is restricted to loopback (got {client_host}). "
            "Set GLC_KILL_ALLOW_REMOTE=1 to override (not recommended).",
        )
    # Send SIGTERM to ourselves shortly after returning so the client gets a 200.
    import asyncio

    async def _shoot() -> None:
        await asyncio.sleep(0.2)
        os.kill(os.getpid(), signal.SIGTERM)

    asyncio.create_task(_shoot())
    return {"status": "terminating", "pid": os.getpid()}
