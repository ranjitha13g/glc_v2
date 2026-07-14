"""Shared FastAPI dependency for install-token authentication.

Apply to any router with:
    app.include_router(router, dependencies=[Depends(require_token)])
"""

from __future__ import annotations

import hmac

from fastapi import Header, HTTPException

from glc.config import get_or_create_install_token


def require_token(authorization: str | None = Header(default=None)) -> None:
    expected = get_or_create_install_token()
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token (Authorization: Bearer <install_token>)")
    presented = authorization.removeprefix("Bearer ").strip()
    if not hmac.compare_digest(presented, expected):
        raise HTTPException(403, "install token mismatch")
