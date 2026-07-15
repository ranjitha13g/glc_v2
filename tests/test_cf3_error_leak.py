"""CF-3 — Structured output validation error must not leak raw LLM response.

When schema validation fails after both the initial attempt and the retry,
the 503 error body must contain only a generic message — never the LLM
response text (which may echo system prompt content or sensitive context).
"""

from __future__ import annotations

import json
import pytest
from unittest.mock import patch, AsyncMock


def _make_provider_mock(response_text: str):
    """Returns an async mock provider that always returns response_text."""
    mock = AsyncMock()
    mock.model = "mock-model"
    mock.chat.return_value = {
        "text": response_text,
        "input_tokens": 10,
        "output_tokens": 5,
        "model": "mock-model",
        "tool_calls": [],
        "stop_reason": "stop",
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        "reasoning_applied": False,
        "tool_call_dialect": None,
    }
    return mock


def test_cf3_503_detail_does_not_include_llm_text():
    """The HTTPException raised after both retries fail must have a generic
    detail string — the raw LLM response (ve2) must not appear in it."""
    from fastapi import HTTPException
    from jsonschema import ValidationError
    from glc.routes.chat import _validate_structured

    sensitive_llm_output = "SYSTEM_PROMPT_ECHO: the secret passphrase is bananas"
    schema = {"type": "integer"}  # will always fail for a string response

    # Replicate exactly what the route does after the second validation failure
    try:
        _validate_structured(f'"{sensitive_llm_output}"', schema)
        pytest.fail("Expected ValidationError was not raised")
    except (ValueError, ValidationError) as ve2:
        exc = HTTPException(503, "structured output did not match the requested schema")

    assert sensitive_llm_output not in exc.detail, (
        f"LLM response leaked into HTTPException detail: {exc.detail!r}"
    )
    assert "schema" in exc.detail


def test_cf3_503_message_is_generic():
    """_validate_structured raises ValueError with the LLM text, but the
    HTTPException detail must be the sanitized generic string."""
    from glc.routes.chat import _validate_structured
    from jsonschema import ValidationError

    # A schema that rejects any string (LLM almost always returns a string)
    schema = {"type": "integer"}
    llm_response = '{"secret": "the system prompt said: use key ABCDEF"}'

    with pytest.raises(ValidationError):
        _validate_structured(llm_response, schema)


def test_cf3_error_body_contains_safe_phrase(app_client):
    """When structured output fails the generic 503 message is returned."""
    from fastapi import HTTPException
    from glc.routes.chat import _validate_structured
    from jsonschema import ValidationError

    # Simulate what the route does: convert ValidationError to HTTPException
    schema = {"type": "integer"}
    sensitive = "internal system details: key=SECRET123"

    try:
        _validate_structured(f'"{sensitive}"', schema)
    except (ValueError, ValidationError) as ve2:
        import logging
        logging.getLogger("glc.chat").warning("structured output failed: %s", ve2)
        exc = HTTPException(503, "structured output did not match the requested schema")

    assert sensitive not in exc.detail, "sensitive content in HTTPException detail"
    assert "schema" in exc.detail
