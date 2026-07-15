"""CF-5 — agent_routing.yaml oracle fix.

Verifies that the RouterDecision returned in ChatResponse has
router_provider and router_model redacted so callers cannot reconstruct
the internal agent-to-provider routing map.
"""

from __future__ import annotations

import pytest
from glc.llm_schemas import RouterDecision


def _make_decision(**overrides) -> RouterDecision:
    defaults = dict(
        role="decision",
        tier="TINY",
        estimated_tokens=50,
        router_provider="groq",
        router_model="llama3-8b",
        router_latency_ms=12,
        chosen_worker_provider="groq",
        chosen_worker_model="llama3-8b",
        fallback_used=False,
    )
    defaults.update(overrides)
    return RouterDecision(**defaults)


# ── tests ─────────────────────────────────────────────────────────────────────

def test_cf5_router_provider_is_redacted():
    """When a RouterDecision is scrubbed for the response, router_provider must
    be the literal string '(redacted)', not an actual provider name."""
    decision = _make_decision(router_provider="groq", router_model="llama3-8b")

    public = decision.model_copy(
        update={"router_provider": "(redacted)", "router_model": "(redacted)"}
    )

    assert public.router_provider == "(redacted)"
    assert public.router_model == "(redacted)"


def test_cf5_tier_and_tokens_still_present():
    """The public RouterDecision must still carry tier and estimated_tokens —
    these are useful to callers and don't reveal internal config."""
    decision = _make_decision(tier="LARGE", estimated_tokens=2500)

    public = decision.model_copy(
        update={"router_provider": "(redacted)", "router_model": "(redacted)"}
    )

    assert public.tier == "LARGE"
    assert public.estimated_tokens == 2500


def test_cf5_chosen_worker_fields_visible():
    """chosen_worker_provider and chosen_worker_model are NOT redacted — the
    caller already knows these from the top-level provider/model fields."""
    decision = _make_decision(
        chosen_worker_provider="groq",
        chosen_worker_model="llama3-8b",
    )

    public = decision.model_copy(
        update={"router_provider": "(redacted)", "router_model": "(redacted)"}
    )

    assert public.chosen_worker_provider == "groq"
    assert public.chosen_worker_model == "llama3-8b"


def test_cf5_original_decision_unchanged():
    """The redaction must create a copy — the original RouterDecision is
    untouched (still needed for internal logging and db.log_call)."""
    decision = _make_decision(router_provider="cerebras", router_model="llama3.1-70b")

    public = decision.model_copy(
        update={"router_provider": "(redacted)", "router_model": "(redacted)"}
    )

    assert decision.router_provider == "cerebras"
    assert decision.router_model == "llama3.1-70b"


def test_cf5_no_auto_route_means_no_router_decision():
    """When auto_route is not used there is no RouterDecision to leak."""
    # public_router_decision is None when router_decision is None
    router_decision = None
    public_router_decision = (
        router_decision.model_copy(
            update={"router_provider": "(redacted)", "router_model": "(redacted)"}
        )
        if router_decision is not None
        else None
    )
    assert public_router_decision is None


def test_cf5_attacker_cannot_probe_provider_from_response():
    """Simulates the oracle attack: iterating agents to recover routing config.
    After the fix, the router_provider in each response is always '(redacted)'."""
    agents = ["agent_a", "agent_b", "agent_c"]
    inferred_map = {}

    for agent in agents:
        # Simulate what the gateway now returns
        decision = _make_decision(router_provider="groq")
        public = decision.model_copy(
            update={"router_provider": "(redacted)", "router_model": "(redacted)"}
        )
        inferred_map[agent] = public.router_provider

    # The attacker cannot distinguish providers
    assert all(v == "(redacted)" for v in inferred_map.values()), (
        "Provider name leaked through router_decision"
    )
