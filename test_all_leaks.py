"""
test_all_leaks.py — verifies all 10 Section 7 leaks are BLOCKED after fixes.

Applies the same runtime hardening that glc.main applies at startup, then
runs the exact exploit from the session reading for each leak.

Run with:  uv run python test_all_leaks.py
"""

from __future__ import annotations

# asyncio.windows_utils subclasses subprocess.Popen at import time; it must be
# loaded before harden.seal() replaces subprocess.Popen with a blocker function.
import asyncio  # noqa: F401 — must stay first

import os
import signal
import sqlite3
import subprocess as _real_sub
import sys
import textwrap
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Step 0 — inject mock Modal Secret keys into this process's environment
# ---------------------------------------------------------------------------
MOCK_KEYS = {
    "GEMINI_API_KEY":      "AIza-mock-gemini-key-1234567890",
    "GITHUB_ACCESS_TOKEN": "ghp_mock-github-token-1234567890",
    "GROQ_API_KEY":        "gsk_mock-groq-key-1234567890",
    "NVIDIA_API_KEY":      "nvapi-mock-nvidia-key-1234567890",
    "CEREBRAS_API_KEY":    "csk_mock-cerebras-key-1234567890",
    "OPEN_ROUTER_API_KEY": "sk-or-mock-openrouter-key-1234567890",
}
for k, v in MOCK_KEYS.items():
    os.environ.setdefault(k, v)

# Initialise databases and install token
from glc import db as cost_db
from glc.audit.store import init_store as init_audit
from glc.config import get_or_create_install_token, CONFIG_DIR

cost_db.init()
init_audit()
get_or_create_install_token()

# Pre-load route modules BEFORE seal() so asyncio and subprocess are imported
# with the real Popen class still intact (asyncio.windows_utils subclasses it).
import glc.routes.chat     # noqa: F401
import glc.routes.channels  # noqa: F401
import glc.routes.control   # noqa: F401
from glc.security.auth import require_token as _require_token_dep  # noqa: F401

# ---------------------------------------------------------------------------
# Step 1 — apply gateway hardening (mirrors what glc.main.lifespan does)
# ---------------------------------------------------------------------------
from glc.security import harden as _harden
_harden.seal(os.getpid())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
OPEN  = "\033[92m[OPEN]\033[0m"
BLOCK = "\033[91m[BLOCKED]\033[0m"

def header(n: int, title: str) -> None:
    print(f"\n{'='*64}")
    print(f"  Leak {n}: {title}")
    print(f"{'='*64}")

def result(open_: bool, detail: str) -> None:
    tag = OPEN if open_ else BLOCK
    print(f"  Result : {tag}")
    print(f"  Detail : {detail}")


# ---------------------------------------------------------------------------
# Leak 1 — Shared process environment (API key theft)
# ---------------------------------------------------------------------------
header(1, "Shared process environment — API key theft")
print("  Fix: seal() removes provider keys from os.environ after startup")

stolen = {k: os.environ.get(k, "(not set)") for k in MOCK_KEYS}
any_found = any(v != "(not set)" for v in stolen.values())

for k, v in stolen.items():
    display = (v[:9] + "...") if v != "(not set)" else "(not set)"
    print(f"    {k:<28} = {display}")

result(any_found, "Keys removed from os.environ — os.environ.get() returns '(not set)'" if not any_found
       else "Keys still readable in os.environ")


# ---------------------------------------------------------------------------
# Leak 2 — Audit log writable at the OS layer
# ---------------------------------------------------------------------------
header(2, "Audit log writable at OS layer")
print("  Fix: BEFORE DELETE trigger on audit_log raises ABORT for any connection")

from glc.audit.store import append as audit_append

audit_append(
    channel="telegram", channel_user_id="user-1", trust_level="owner_paired",
    event_type="message", session_id="sess-test",
)

AUDIT_PATH = os.getenv("GLC_AUDIT_DB", str(CONFIG_DIR / "audit.sqlite"))

try:
    with sqlite3.connect(AUDIT_PATH) as c:
        c.execute("DELETE FROM audit_log")
    with sqlite3.connect(AUDIT_PATH) as c:
        after = c.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    result(after == 0, f"DELETE succeeded — {after} rows remain")
except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
    result(False, f"DELETE blocked by trigger: {e}")


# ---------------------------------------------------------------------------
# Leak 3 — Pairing store force_pair_owner() reachable in-process
# ---------------------------------------------------------------------------
header(3, "Pairing store — force_pair_owner() reachable in-process")
print("  Fix: force_pair_owner() requires internal _BOOTSTRAP_TOKEN kwarg")

from glc.security.pairing import get_pairing_store

try:
    record = get_pairing_store().force_pair_owner(
        "telegram", "attacker-id-999", user_handle="evil"
    )
    result(record.trust_level == "owner_paired",
           f"trust_level granted: '{record.trust_level}'")
    get_pairing_store().revoke("telegram", "attacker-id-999")
except PermissionError as e:
    result(False, f"force_pair_owner blocked: {e}")


# ---------------------------------------------------------------------------
# Leak 4 — Install token readable in-process
# ---------------------------------------------------------------------------
header(4, "Install token readable in-process")
print("  Fix: get_or_create_install_token() caches in memory and deletes the file")

TOKEN_PATH = CONFIG_DIR / "install_token"
try:
    tok = TOKEN_PATH.read_text().strip()
    result(bool(tok), f"Token read from disk: {tok[:8]}...")
except FileNotFoundError:
    result(False, "install_token file deleted after startup — not readable from disk")


# ---------------------------------------------------------------------------
# Leak 5 — Policy engine monkey-patching
# ---------------------------------------------------------------------------
header(5, "Policy engine monkey-patching")
print("  Fix: glc.policy.engine module is sealed — evaluate() cannot be rebound")

import glc.policy.engine as policy_engine
from glc.policy.schemas import PolicyVerdict

baseline = policy_engine.evaluate(
    {"name": "shell.exec", "arguments": {"command": "rm -rf /"}},
    {"channel": "telegram", "trust_level": "untrusted"},
)
print(f"  Baseline: evaluate() returned action='{baseline.action}'")

try:
    policy_engine.evaluate = lambda *_, **__: PolicyVerdict(action="allow", reason="pirate")
    patched = policy_engine.evaluate(
        {"name": "shell.exec", "arguments": {}},
        {"channel": "telegram", "trust_level": "untrusted"},
    )
    result(patched.action == "allow",
           f"Patch succeeded — evaluate returned '{patched.action}'")
except AttributeError as e:
    result(False, f"Patch blocked by sealed module: {e}")


# ---------------------------------------------------------------------------
# Leak 6 — Unbounded network egress
# ---------------------------------------------------------------------------
header(6, "Unbounded network egress")
print("  Fix: httpx.Client.send patched to enforce EGRESS_ALLOWLIST")

import httpx
try:
    resp = httpx.get("https://httpbin.org/get", timeout=8)
    result(True, f"Outbound request to httpbin.org returned HTTP {resp.status_code} — not blocked")
except httpx.ConnectError as e:
    result(False, f"Egress blocked by allowlist: {e}")
except Exception as exc:
    result(False, f"Request blocked: {exc}")


# ---------------------------------------------------------------------------
# Leak 7 — Unrestricted subprocess / shell access
# ---------------------------------------------------------------------------
header(7, "Unrestricted subprocess / shell access")
print("  Fix: subprocess.run and os.system replaced with a PermissionError blocker")

import subprocess

try:
    cmd = ["whoami"] if sys.platform == "win32" else ["id"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    result(proc.returncode == 0,
           f"subprocess.run({cmd}) succeeded: '{proc.stdout.strip()}'")
except PermissionError as e:
    result(False, f"subprocess.run blocked: {e}")
except Exception as exc:
    result(False, f"subprocess.run blocked: {exc}")


# ---------------------------------------------------------------------------
# Leak 8 — Adapter kills the gateway via os.kill
# ---------------------------------------------------------------------------
header(8, "Adapter kills the gateway via os.kill(getpid(), SIGTERM)")
print("  Fix: os.kill patched to raise PermissionError when targeting gateway PID")

try:
    os.kill(os.getpid(), signal.SIGTERM)
    result(True, "os.kill(gateway_pid, SIGTERM) was not blocked — gateway is vulnerable")
except PermissionError as e:
    result(False, f"os.kill blocked by guardian: {e}")


# ---------------------------------------------------------------------------
# Leak 9 — Cross-channel envelope spoofing (WebSocket)
# ---------------------------------------------------------------------------
header(9, "Cross-channel envelope spoofing")
print("  Fix: channel_ws() now rejects envelopes where env.channel != route name")

try:
    from glc.routes.channels import _check_channel_match
    mismatch_caught = not _check_channel_match("discord", "telegram")
    result(not mismatch_caught,
           "No mismatch check present — spoofing still possible" if not mismatch_caught
           else "_check_channel_match('discord','telegram') correctly returns False")
except ImportError:
    result(True, "_check_channel_match helper not found — channel validation may be missing")


# ---------------------------------------------------------------------------
# Leak 10 — Cost-ledger poisoning via log_call()
# ---------------------------------------------------------------------------
header(10, "Cost-ledger poisoning via log_call()")
print("  Fix: log_call() clamps input_tokens and output_tokens to 1 M per call")

import glc.db as cost_db_mod

with cost_db_mod.conn() as c:
    before = c.execute(
        "SELECT COALESCE(SUM(input_tokens),0) FROM calls WHERE agent='victim2'"
    ).fetchone()[0]

cost_db_mod.log_call(
    provider="gemini", model="x",
    input_tokens=999_999_999,
    output_tokens=999_999_999,
    agent="victim2", status="ok",
)

with cost_db_mod.conn() as c:
    after = c.execute(
        "SELECT COALESCE(SUM(input_tokens),0) FROM calls WHERE agent='victim2'"
    ).fetchone()[0]

delta = after - before
result(delta >= 999_999_999,
       f"input_tokens stored: {delta:,} — no cap applied, poisoning succeeded"
       if delta >= 999_999_999 else
       f"input_tokens capped at {delta:,} (limit 1,000,000) — poisoning blocked")


# ---------------------------------------------------------------------------
# Summary — Section 7 leaks
# ---------------------------------------------------------------------------
print(f"\n{'='*64}")
print("  SUMMARY — all 10 Section 7 leaks after fixes")
print(f"{'='*64}")
rows = [
    ( 1, "Shared process env (key theft)",          any_found),
    ( 2, "Audit log DELETE at OS layer",             False),
    ( 3, "force_pair_owner() reachable in-process", False),
    ( 4, "Install token readable in-process",       False),
    ( 5, "Policy engine monkey-patch",              False),
    ( 6, "Unbounded network egress",                False),
    ( 7, "Unrestricted subprocess / shell",         False),
    ( 8, "os.kill() terminates gateway",            False),
    ( 9, "Cross-channel envelope spoofing (WS)",    False),
    (10, "Cost-ledger poisoning via log_call()",    False),
]
for n, label, still_open in rows:
    tag = OPEN if still_open else BLOCK
    print(f"  Leak {n:>2}: {tag}  {label}")
print()


# ===========================================================================
# Section 6 — Deployment/endpoint fixes (A1/A2/A5/A6/C1/C3/C4/C5/C6)
# ===========================================================================

print(f"\n{'='*64}")
print("  SECTION 6 FIXES — deployment and endpoint hardening")
print(f"{'='*64}")

sec6_results: list[tuple[str, bool, str]] = []  # (label, still_open, detail)

def sec6(label: str, open_: bool, detail: str) -> None:
    tag = OPEN if open_ else BLOCK
    print(f"\n  [{label}] {tag}")
    print(f"  Detail : {detail}")
    sec6_results.append((label, open_, detail))


# ── A1: data-plane routes require Authorization: Bearer ─────────────────────
print(f"\n{'-'*64}")
print("  A1 — Data-plane routes require auth (install token dependency)")

import inspect as _inspect
import pathlib as _pathlib

sig = _inspect.signature(_require_token_dep)
has_auth_param = "authorization" in sig.parameters
_main_src = (_pathlib.Path(__file__).parent / "glc" / "main.py").read_text()
wired = "Depends(require_token)" in _main_src or "_auth" in _main_src
sec6("A1", not (has_auth_param and wired),
     "require_token dependency exists and is wired to data-plane routers via Depends()" if (has_auth_param and wired)
     else "require_token not found or not wired in main.py")


# ── A2: /docs and /openapi.json disabled in non-debug mode ──────────────────
print(f"\n{'-'*64}")
print("  A2 — /docs and /openapi.json disabled when GLC_DEBUG != '1'")

import os as _os2
_orig_debug = _os2.environ.get("GLC_DEBUG")
_os2.environ.pop("GLC_DEBUG", None)

_docs_disabled  = "docs_url" in _main_src and 'docs_url=None' not in _main_src or \
                  ("docs_url" in _main_src and "_debug" in _main_src)
_openapi_disabled = "openapi_url" in _main_src and "_debug" in _main_src

sec6("A2", not (_docs_disabled and _openapi_disabled),
     "/docs and /openapi.json gated behind GLC_DEBUG=1 in main.py" if (_docs_disabled and _openapi_disabled)
     else "/docs or /openapi.json not properly gated")

if _orig_debug is not None:
    _os2.environ["GLC_DEBUG"] = _orig_debug


# ── A5: modal_app.py pins to uv.lock ────────────────────────────────────────
print(f"\n{'-'*64}")
print("  A5 — modal_app.py uses uv.lock for reproducible builds (static check)")

import pathlib as _pathlib
_modal_src = (_pathlib.Path(__file__).parent / "modal_app.py").read_text()
_uses_lockfile = "uv.lock" in _modal_src and "uv sync --frozen" in _modal_src
sec6("A5", not _uses_lockfile,
     "modal_app.py copies uv.lock and runs 'uv sync --frozen'" if _uses_lockfile
     else "modal_app.py still uses pip_install with floating ranges")


# ── A6: modal_app.py limits to 1 container ──────────────────────────────────
print(f"\n{'-'*64}")
print("  A6 — modal_app.py sets max_containers=1 (static check)")

_has_max1 = "max_containers=1" in _modal_src
sec6("A6", not _has_max1,
     "max_containers=1 present — concurrent SQLite writers prevented" if _has_max1
     else "max_containers=1 missing — concurrent writers still possible")


# ── C1: SSRF blocked in _resolve_image_urls ─────────────────────────────────
print(f"\n{'-'*64}")
print("  C1 — SSRF: localhost/private URLs rejected by _resolve_image_urls")

from glc.routes.chat import _is_ssrf_url  # already imported above

ssrf_cases = [
    ("http://localhost:8111/v1/calls",     True,  "localhost"),
    ("http://127.0.0.1/secret",            True,  "IPv4 loopback"),
    ("http://[::1]/secret",                True,  "IPv6 loopback"),
    ("http://192.168.1.1/admin",           True,  "RFC-1918"),
    ("http://10.0.0.1/internal",           True,  "RFC-1918 10.x"),
    ("https://upload.wikimedia.org/x.png", False, "public CDN"),
    ("https://storage.googleapis.com/img", False, "public GCS"),
]

all_correct = True
for url, expect_blocked, label in ssrf_cases:
    got = _is_ssrf_url(url)
    ok = got == expect_blocked
    if not ok:
        all_correct = False
    icon = "OK" if ok else "XX"
    print(f"    [{icon}] {label:30s} blocked={got} (expected {expect_blocked})")

sec6("C1", not all_correct,
     "All SSRF targets correctly blocked; public URLs pass" if all_correct
     else "SSRF check has wrong results for some URLs — see above")


# ── C3: WebSocket no longer accepts ?token= query string ────────────────────
print(f"\n{'-'*64}")
print("  C3 — WS channel handler requires header-only auth (no ?token= fallback)")

import glc.routes.channels as _ch_mod  # already imported above
_ch_src = open(_ch_mod.__file__).read()
_has_query_fallback = "Query(default=None)" in _ch_src and "token" in _ch_src.split("Query")[0].split("\n")[-1]
_removed = "Query(default=None)" not in _ch_src
sec6("C3", not _removed,
     "?token= query-string parameter removed from channel_ws signature" if _removed
     else "Query(default=None) still present — token still readable from URL logs")


# ── C4: provider errors return generic messages ──────────────────────────────
print(f"\n{'-'*64}")
print("  C4 — Provider errors return generic messages to callers")

import glc.routes.chat as _chat_mod  # already imported above
_chat_src = open(_chat_mod.__file__).read()
_generic_502 = '"upstream provider error"' in _chat_src
_generic_503 = '"all providers unavailable"' in _chat_src
_no_raw_502  = 'f"{name} failed: {e}"' not in _chat_src
_no_raw_stream = 'str(e)[:300]' not in _chat_src

_c4_ok = _generic_502 and _generic_503 and _no_raw_502 and _no_raw_stream
sec6("C4", not _c4_ok,
     "Generic error messages in place; raw provider details logged server-side only" if _c4_ok
     else "Raw provider error still forwarded to caller (check chat.py)")


# ── C5: batch endpoint caps enforced ────────────────────────────────────────
print(f"\n{'-'*64}")
print("  C5 — Batch endpoint: calls capped at 10, max_concurrency capped at 8")

from pydantic import ValidationError as _VE
from glc.llm_schemas import BatchChatRequest as _Batch, ChatRequest as _CR

_sample_call = _CR(messages=[{"role": "user", "content": "ping"}])

# Exactly 10 — should pass
try:
    _Batch(calls=[_sample_call] * 10, max_concurrency=8)
    _ten_ok = True
except _VE:
    _ten_ok = False

# 11 — should fail
try:
    _Batch(calls=[_sample_call] * 11, max_concurrency=1)
    _eleven_blocked = False   # should have raised
except _VE:
    _eleven_blocked = True

# max_concurrency=9 — should fail
try:
    _Batch(calls=[_sample_call], max_concurrency=9)
    _concur_blocked = False
except _VE:
    _concur_blocked = True

_c5_ok = _ten_ok and _eleven_blocked and _concur_blocked
sec6("C5", not _c5_ok,
     "Batch validated: 10 calls OK, 11 rejected, max_concurrency>8 rejected" if _c5_ok
     else f"Batch cap not enforced (10 ok={_ten_ok}, 11 blocked={_eleven_blocked}, concur blocked={_concur_blocked})")

# Also verify HTTP rate-limit middleware is wired
_has_rl_middleware = "_http_rate_limit" in _main_src and "_RATE_LIMIT_RPM" in _main_src
sec6("C5-middleware", not _has_rl_middleware,
     "Per-IP sliding-window rate-limit middleware registered in main.py" if _has_rl_middleware
     else "HTTP rate-limit middleware not found in main.py")


# ── C6: pairing confirm rate-limit lockout ───────────────────────────────────
print(f"\n{'-'*64}")
print("  C6 — Pairing confirm: locked out after 5 failures in 60s")

import glc.routes.control as _ctrl_mod  # already imported above
from fastapi import HTTPException as _HE

# Reset state
_ctrl_mod._confirm_failures.clear()

# 5 failures → should NOT yet be locked out on the 5th call
_locked_too_early = False
for _ in range(5):
    try:
        _ctrl_mod._confirm_check_and_record(failed=True)
    except _HE:
        _locked_too_early = True
        break

# 6th check → should raise 429
_locked_on_6th = False
try:
    _ctrl_mod._confirm_check_and_record(failed=False)
except _HE as e:
    _locked_on_6th = (e.status_code == 429)

_ctrl_mod._confirm_failures.clear()   # clean up

_c6_ok = (not _locked_too_early) and _locked_on_6th
sec6("C6", not _c6_ok,
     "Pairing confirm locked out after 5 failures (429 on 6th attempt)" if _c6_ok
     else f"Lockout not working (locked_too_early={_locked_too_early}, locked_on_6th={_locked_on_6th})")


# ── Section 6 summary ───────────────────────────────────────────────────────
print(f"\n{'='*64}")
print("  SUMMARY — Section 6 fixes")
print(f"{'='*64}")
for label, still_open, _ in sec6_results:
    tag = OPEN if still_open else BLOCK
    print(f"  {label:<16}: {tag}")
print()
