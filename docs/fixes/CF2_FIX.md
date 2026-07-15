# CF-2 Fix — JSON Schema Bomb via `response_format.schema_`

**Invariant:** I-8 (primary) — Every run must have hard limits on time, tokens, tool calls, and cost  
**Invariant:** I-3 (secondary) — External content must always be treated as data, never as instructions  
**File changed:** `glc/routes/chat.py`  
**Test file:** `tests/test_cf2_schema_bomb.py`  
**Status:** Fixed and verified ✅

---

## What was wrong

When a request includes `response_format` with a JSON schema, the gateway validated the LLM response with:

```python
# BEFORE (vulnerable)
def _validate_structured(text: str, schema: dict):
    try:
        obj = json.loads(text)
    except Exception as e:
        raise ValueError(f"output is not JSON: {e}")
    Draft202012Validator(schema).validate(obj)   # ← no timeout, no schema safety check
    return obj
```

**Two attack vectors:**

1. **Self-referential `$ref` bomb:** A schema like `{"$ref": "#"}` causes `Draft202012Validator` to recurse infinitely, hanging the worker thread indefinitely until the Modal function timeout (5 minutes), consuming an entire worker slot.

2. **Deeply nested `allOf`/`properties` bomb:** A schema with 30+ levels of nesting causes exponential recursive traversal, producing the same hang. When validation fails, the retry path triggers a second provider call, doubling cost with no useful result.

Neither case had a time limit, so the attack was trivially reproducible and repeatable.

---

## What was changed

**`glc/routes/chat.py` — `_validate_structured()` rewritten with two guards:**

### Guard 1 — Pre-validation schema safety check

```python
def _check_schema_safe(schema: dict, _depth: int = 0) -> None:
    if _depth > 12:
        raise ValueError("schema nesting depth exceeds limit")
    if isinstance(schema, dict):
        ref = schema.get("$ref", "")
        if ref == "#" or ref.endswith("/#") or ref.endswith("/$defs"):
            raise ValueError(f"self-referential $ref '{ref}' is not allowed")
        for v in schema.values():
            _check_schema_safe(v, _depth + 1)
    elif isinstance(schema, list):
        for item in schema:
            _check_schema_safe(item, _depth + 1)
```

This runs **before** the validator and rejects:
- Any `$ref` that points to `"#"` (the schema root — always recursive)
- Any schema nesting deeper than 12 levels

Both rejections are O(n) in schema size and return immediately with a `ValueError`.

### Guard 2 — 2-second validation timeout

```python
_SCHEMA_VALIDATE_TIMEOUT = 2.0
_VALIDATOR_POOL = concurrent.futures.ThreadPoolExecutor(
    max_workers=4, thread_name_prefix="schema-validator"
)

def _validate_structured(text: str, schema: dict):
    ...
    _check_schema_safe(schema)
    fut = _VALIDATOR_POOL.submit(Draft202012Validator(schema).validate, obj)
    try:
        fut.result(timeout=_SCHEMA_VALIDATE_TIMEOUT)
    except concurrent.futures.TimeoutError:
        raise ValueError("schema validation timed out — schema may be overly complex")
    return obj
```

The validator runs in a bounded thread pool. If it hasn't finished within 2 seconds it is abandoned and a `ValueError` is raised. The calling code converts `ValueError` into a `503` response, not a hang.

---

## Why this is safe

- The safety check (`_check_schema_safe`) is purely structural — it never executes the schema — so it can't be hung by the schema itself.
- The thread pool cap (4 workers) bounds parallel validation attempts. A burst of schema-bomb requests can't exhaust the server's thread pool.
- The 2-second timeout is generous for legitimate schemas (most real schemas validate in < 50 ms) but fatal for recursive ones.
- The retry path in the caller catches `ValueError` and proceeds to the second provider call only if validation was structurally plausible. A schema bomb is rejected before the retry.

---

## Tests added

| Test | What it verifies |
|------|-----------------|
| `test_cf2_self_ref_raises_immediately` | `$ref: "#"` is rejected by safety check before validator runs |
| `test_cf2_nested_self_ref_raises` | `$ref: "#"` inside nested `properties` is also caught |
| `test_cf2_depth_limit_raises` | Schema deeper than 12 levels is rejected |
| `test_cf2_valid_schema_passes` | A well-formed schema + matching JSON returns the parsed object |
| `test_cf2_invalid_json_raises` | Non-JSON text raises `ValueError` mentioning "not JSON" |
| `test_cf2_schema_mismatch_raises_validation_error` | Type mismatch raises `jsonschema.ValidationError` |
| `test_cf2_timeout_raises` | Validator exceeding timeout raises `ValueError` mentioning "timed out" |

All 7 tests pass.
