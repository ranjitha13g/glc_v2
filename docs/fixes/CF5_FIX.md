# CF-5 Fix — `agent_routing.yaml` Oracle via `router_decision` in Response

**Invariant:** I-5 (primary) — Every stored fact must record its source  
**Invariant:** I-2 (secondary) — Every action must be checked against the actual user, tenant, and final arguments  
**File changed:** `glc/routes/chat.py`  
**Test file:** `tests/test_cf5_routing_oracle.py`  
**Status:** Fixed and verified ✅

---

## What was wrong

When `auto_route=true`, the gateway returned a `RouterDecision` object in the `ChatResponse` that included the internal routing fields:

```python
# BEFORE (vulnerable) — ChatResponse included full RouterDecision
return ChatResponse(
    ...
    router_decision=router_decision,   # ← exposes router_provider, router_model
).model_dump()
```

`RouterDecision` has two sensitive fields:
- `router_provider` — the name of the LLM provider used for tier classification (e.g., `"groq"`, `"cerebras"`)
- `router_model` — the model name used for that classification call

An attacker who can make `/v1/chat` requests can iterate over agent names and observe `router_decision.router_provider` in each response. Combined with the top-level `provider` field, they can reconstruct the complete `agent_routing.yaml` mapping — which agents route to which providers, what fallback order is used, and what the cost profile of each request type is.

**Attack pattern:**
```
POST /v1/chat {"agent": "code_agent", "auto_route": "decision", ...}
→ response.router_decision.router_provider = "groq"

POST /v1/chat {"agent": "vision_agent", "auto_route": "decision", ...}
→ response.router_decision.router_provider = "gemini"

... repeat for all agent names → full routing map extracted
```

---

## What was changed

**`glc/routes/chat.py` — added `public_router_decision` copy before the response:**

```python
# CF-5: scrub internal routing fields before sending to caller
public_router_decision = (
    router_decision.model_copy(
        update={"router_provider": "(redacted)", "router_model": "(redacted)"}
    )
    if router_decision is not None
    else None
)
```

And the response now uses `public_router_decision` instead of `router_decision`:

```python
return ChatResponse(
    ...
    router_decision=public_router_decision,   # ← redacted copy
).model_dump()
```

The original `router_decision` object is unchanged — it is still used for `db.log_call()` (server-side logging) and for the internal `router_decision.chosen_worker_provider` / `router_decision.chosen_worker_model` fields.

---

## What remains visible to callers

The public `RouterDecision` still carries:
- `tier` — TINY, LARGE, or HUGE (useful for understanding cost)
- `estimated_tokens` — the token estimate used
- `chosen_worker_provider` / `chosen_worker_model` — the actual provider used (already visible in top-level `provider`/`model` fields anyway)
- `router_latency_ms` — how long routing classification took
- `fallback_used` — whether the router LLM was skipped

These fields are informative to the caller without revealing internal configuration.

---

## Why this is safe

- `router_provider` and `router_model` reveal which LLM is used internally for routing decisions — a separate internal service the caller never needs to know about.
- `model_copy()` creates a new Pydantic model instance. The original is unaffected and still written to the audit log with full detail.
- The redaction is unconditional — all callers get the same view. A future owner-trust gate can be layered on top without changing the fix.

---

## Tests added

| Test | What it verifies |
|------|-----------------|
| `test_cf5_router_provider_is_redacted` | After scrubbing, `router_provider` is `"(redacted)"` |
| `test_cf5_tier_and_tokens_still_present` | `tier` and `estimated_tokens` survive redaction |
| `test_cf5_chosen_worker_fields_visible` | `chosen_worker_provider`/`chosen_worker_model` are NOT redacted |
| `test_cf5_original_decision_unchanged` | `model_copy` does not mutate the original `RouterDecision` |
| `test_cf5_no_auto_route_means_no_router_decision` | `None` router_decision → `None` public decision (no crash) |
| `test_cf5_attacker_cannot_probe_provider_from_response` | Simulated oracle attack yields only `"(redacted)"` across all agents |

All 6 tests pass.
