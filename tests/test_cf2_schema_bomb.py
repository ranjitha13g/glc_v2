"""CF-2 — JSON schema bomb fix.

Verifies that _validate_structured():
  - rejects self-referential $ref schemas immediately
  - rejects excessively deep schemas immediately
  - enforces a 2-second timeout on slow validators
  - passes valid schemas normally
"""

from __future__ import annotations

import pytest


def test_cf2_self_ref_raises_immediately():
    """A $ref: '#' schema must be rejected before validation starts."""
    from glc.routes.chat import _validate_structured

    bomb = {"$ref": "#"}
    with pytest.raises(ValueError, match="self-referential"):
        _validate_structured('{"x": 1}', bomb)


def test_cf2_nested_self_ref_raises():
    """A deeply-nested self-referential schema must also be caught."""
    from glc.routes.chat import _validate_structured

    bomb = {"properties": {"a": {"$ref": "#"}}}
    with pytest.raises(ValueError, match="self-referential"):
        _validate_structured('{"a": 1}', bomb)


def test_cf2_depth_limit_raises():
    """A schema nested beyond 12 levels must be rejected."""
    from glc.routes.chat import _validate_structured

    # Build a schema 15 levels deep
    deep: dict = {"type": "string"}
    for _ in range(15):
        deep = {"properties": {"x": deep}}
    with pytest.raises(ValueError, match="nesting depth"):
        _validate_structured('{}', deep)


def test_cf2_valid_schema_passes():
    """A well-formed schema with a matching object must pass without error."""
    from glc.routes.chat import _validate_structured

    schema = {
        "type": "object",
        "properties": {"name": {"type": "string"}, "age": {"type": "integer"}},
        "required": ["name"],
    }
    result = _validate_structured('{"name": "Alice", "age": 30}', schema)
    assert result == {"name": "Alice", "age": 30}


def test_cf2_invalid_json_raises():
    """Non-JSON text must raise ValueError mentioning JSON."""
    from glc.routes.chat import _validate_structured

    with pytest.raises(ValueError, match="not JSON"):
        _validate_structured("not json at all", {"type": "object"})


def test_cf2_schema_mismatch_raises_validation_error():
    """A JSON value that violates the schema must raise jsonschema.ValidationError."""
    from jsonschema import ValidationError
    from glc.routes.chat import _validate_structured

    schema = {"type": "object", "properties": {"count": {"type": "integer"}}, "required": ["count"]}
    with pytest.raises(ValidationError):
        _validate_structured('{"count": "not-an-int"}', schema)


def test_cf2_timeout_raises(monkeypatch):
    """A validator that exceeds the timeout must raise ValueError about timeout."""
    import concurrent.futures
    from glc.routes import chat as chat_mod

    original_timeout = chat_mod._SCHEMA_VALIDATE_TIMEOUT
    monkeypatch.setattr(chat_mod, "_SCHEMA_VALIDATE_TIMEOUT", 0.001)

    # A moderately complex allOf schema that takes non-trivial time
    # Monkeypatching timeout to near-zero ensures the timeout path is exercised
    import time

    original_submit = chat_mod._VALIDATOR_POOL.submit

    def slow_submit(fn, *args, **kwargs):
        def delayed(*a, **kw):
            time.sleep(0.05)
            return fn(*a, **kw)
        return original_submit(delayed, *args, **kwargs)

    monkeypatch.setattr(chat_mod._VALIDATOR_POOL, "submit", slow_submit)

    schema = {"type": "object"}
    with pytest.raises(ValueError, match="timed out"):
        chat_mod._validate_structured('{}', schema)
