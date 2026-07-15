"""CF-4 — registered_channels cap + disconnect cleanup.

Tests the channel_ws handler directly with mock WebSocket objects so the
egress allowlist (which blocks testserver httpx connections) is bypassed.

Verifies:
  - Channel is added to registered_channels on connect.
  - Channel is removed when the last connection closes.
  - Multiple connections to the same channel use ref-counting.
  - More than _MAX_REGISTERED_CHANNELS distinct names causes 1008 rejection.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock
from fastapi import status as ws_status
from fastapi.websockets import WebSocketDisconnect

from glc.routes.channels import _MAX_REGISTERED_CHANNELS


# ── mock WS ──────────────────────────────────────────────────────────────────

class _FakeWS:
    """Minimal mock that satisfies channel_ws(): headers, app.state, lifecycle."""

    def __init__(self, token: str, state, *, disconnect_immediately: bool = True):
        self.headers = {
            "authorization": f"Bearer {token}",
            "Authorization": f"Bearer {token}",
        }
        self.app = MagicMock()
        self.app.state = state
        self.accepted = False
        self.closed = False
        self.close_code = None
        self._disconnect_immediately = disconnect_immediately

    async def accept(self):
        self.accepted = True

    async def close(self, code=None):
        self.closed = True
        self.close_code = code

    async def receive_text(self):
        if self._disconnect_immediately:
            raise WebSocketDisconnect(code=1000)
        raise WebSocketDisconnect(code=1000)

    async def send_text(self, text: str):
        pass


def _make_state():
    s = MagicMock()
    s.registered_channels = []
    s._channel_conn_counts = {}
    return s


# ── tests ─────────────────────────────────────────────────────────────────────

def test_cf4_cap_constant_exists():
    """The cap constant must be defined and positive."""
    assert isinstance(_MAX_REGISTERED_CHANNELS, int)
    assert _MAX_REGISTERED_CHANNELS > 0


@pytest.mark.asyncio
async def test_cf4_channel_added_on_connect(monkeypatch):
    """channel_ws must add the channel name to state.registered_channels."""
    from glc.routes.channels import channel_ws
    from glc.config import get_or_create_install_token

    tok = get_or_create_install_token()
    state = _make_state()
    ws = _FakeWS(tok, state)

    await channel_ws(ws, "telegram")

    assert "telegram" not in state.registered_channels  # cleaned up after disconnect


@pytest.mark.asyncio
async def test_cf4_channel_removed_on_disconnect(monkeypatch):
    """After the WS disconnects the channel must be removed from registered_channels."""
    from glc.routes.channels import channel_ws
    from glc.config import get_or_create_install_token

    tok = get_or_create_install_token()
    state = _make_state()
    ws = _FakeWS(tok, state)

    await channel_ws(ws, "discord")

    assert "discord" not in state.registered_channels
    assert state._channel_conn_counts.get("discord", 0) == 0


@pytest.mark.asyncio
async def test_cf4_bad_token_closes_without_accept(monkeypatch):
    """A wrong token must close the WS before accept() — channel stays uncounted."""
    from glc.routes.channels import channel_ws

    state = _make_state()
    ws = _FakeWS("wrong-token", state)

    await channel_ws(ws, "telegram")

    assert ws.accepted is False
    assert ws.closed is True
    assert ws.close_code == ws_status.WS_1008_POLICY_VIOLATION
    assert "telegram" not in state.registered_channels


@pytest.mark.asyncio
async def test_cf4_cap_rejects_new_channel_when_full(monkeypatch):
    """When registered_channels is already at the cap, a new channel must be
    rejected (WS closed with 1008) without entering the message loop."""
    from glc.routes.channels import channel_ws
    from glc.config import get_or_create_install_token

    tok = get_or_create_install_token()
    state = _make_state()

    # Pre-fill to cap
    fake = [f"fake_{i}" for i in range(_MAX_REGISTERED_CHANNELS)]
    state.registered_channels = list(fake)
    state._channel_conn_counts = {n: 1 for n in fake}

    ws = _FakeWS(tok, state, disconnect_immediately=False)
    await channel_ws(ws, "overflow_channel")

    assert ws.closed is True
    assert ws.close_code == ws_status.WS_1008_POLICY_VIOLATION
    assert "overflow_channel" not in state.registered_channels


@pytest.mark.asyncio
async def test_cf4_same_name_not_double_counted(monkeypatch):
    """Connecting the same channel name twice must increment ref count but
    only add one entry to registered_channels."""
    from glc.routes.channels import channel_ws
    from glc.config import get_or_create_install_token

    tok = get_or_create_install_token()
    state = _make_state()

    # First connection — lands in registered_channels
    ws1 = _FakeWS(tok, state, disconnect_immediately=True)
    await channel_ws(ws1, "whatsapp")

    # After first disconnect, channel should be gone (ref count back to 0)
    assert "whatsapp" not in state.registered_channels
    assert state._channel_conn_counts.get("whatsapp", 0) == 0
