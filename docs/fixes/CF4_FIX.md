# CF-4 Fix — `registered_channels` Unbounded + No Disconnect Cleanup

**Invariant:** I-8 (primary) — Every run must have hard limits on time, tokens, tool calls, and cost  
**Invariant:** I-7 (secondary) — Components must not be able to edit or delete their own audit logs  
**File changed:** `glc/routes/channels.py`  
**Test file:** `tests/test_cf4_channel_cap.py`  
**Status:** Fixed and verified ✅

---

## What was wrong

Channel registrations were added to `state.registered_channels` on WebSocket connect but **never removed on disconnect**:

```python
# BEFORE (vulnerable)
registered = list(getattr(state, "registered_channels", []))
if name not in registered:
    registered.append(name)
    state.registered_channels = registered
...
except WebSocketDisconnect:
    return   # ← no cleanup
```

**Two problems:**

1. **No size cap:** An attacker could open thousands of WebSocket connections, each with a unique channel name, growing `state.registered_channels` indefinitely. Memory grows unboundedly and any code that iterates the list degrades linearly.

2. **Stale entries:** After a channel adapter disconnected (crash, network drop, intentional close), its name remained in `registered_channels`. A forensic query asking "which channels are currently active?" would return stale entries, corrupting presence information and incident timelines.

---

## What was changed

**`glc/routes/channels.py` — three sections updated:**

### 1. Cap constant added

```python
_MAX_REGISTERED_CHANNELS = 1_000
```

### 2. Registration block with cap check + ref-counting

```python
counts = dict(getattr(state, "_channel_conn_counts", {}))
if name not in counts:
    registered = list(getattr(state, "registered_channels", []))
    if len(registered) >= _MAX_REGISTERED_CHANNELS:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    registered.append(name)
    state.registered_channels = registered
counts[name] = counts.get(name, 0) + 1
state._channel_conn_counts = counts
```

A separate `_channel_conn_counts` dict tracks how many live connections share each channel name. Adding the same channel name from a second connection increments the count without adding a duplicate to `registered_channels`.

### 3. Cleanup on disconnect/exception

```python
except WebSocketDisconnect:
    pass
finally:
    counts = dict(getattr(state, "_channel_conn_counts", {}))
    counts[name] = max(0, counts.get(name, 1) - 1)
    state._channel_conn_counts = counts
    if counts[name] == 0:
        registered = list(getattr(state, "registered_channels", []))
        if name in registered:
            registered.remove(name)
            state.registered_channels = registered
```

The `finally` block runs on both clean disconnect and any exception. A channel is removed from `registered_channels` only when its ref count drops to zero — preventing premature removal when multiple adapters share one channel name.

---

## Why this is safe

- The cap of 1 000 provides a hard bound on memory growth. Legitimate deployments with dozens of channel types are nowhere near this limit.
- Ref-counting ensures that if two WebSocket connections both serve `channel=telegram`, the name stays registered until the last connection closes — no premature removal.
- The `finally` block runs even if the WebSocket handler raises an unexpected exception — no leaks through error paths.

---

## Tests added

| Test | What it verifies |
|------|-----------------|
| `test_cf4_cap_constant_exists` | `_MAX_REGISTERED_CHANNELS` is defined and positive |
| `test_cf4_channel_added_on_connect` | Channel is registered during connection; cleaned up after disconnect |
| `test_cf4_channel_removed_on_disconnect` | After disconnect `registered_channels` and `_channel_conn_counts` are both cleaned |
| `test_cf4_bad_token_closes_without_accept` | Wrong token is rejected with WS_1008 without registering the channel |
| `test_cf4_cap_rejects_new_channel_when_full` | When at cap, new channel is closed with WS_1008 without entering message loop |
| `test_cf4_same_name_not_double_counted` | Single connection ref-counts correctly to zero on disconnect |

All 6 tests pass.
