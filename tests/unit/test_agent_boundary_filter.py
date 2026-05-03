"""Test the agent -> tool boundary pre-filter.

Defense-in-depth claim from the README: every string argument the LLM
emits is scanned through the security gates BEFORE dispatching to the
underlying tool. Adversarial payloads (SSRF, injection, traversal,
cmd-injection) are blocked at this boundary even if the alert payload
itself was accepted at ingest.

This test mocks the SIFT pre-filter to control the gate decision
deterministically — no live API call needed.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from pq_sift_defender.agent.core import IRAgent


def _scan(recommendation: str, risk_score: float = 0.85) -> SimpleNamespace:
    """Build a fake SiftDecision-shaped object."""
    return SimpleNamespace(
        allow=(recommendation == "PASS"),
        scan=SimpleNamespace(
            recommendation=recommendation,
            risk_score=risk_score,
            latency_us=42.0,
            flags=[],
        ),
    )


@pytest.fixture
def stub_chain():
    chain = MagicMock()
    chain.append = MagicMock(return_value=SimpleNamespace(entry_index=0, entry_hash="x"))
    chain.chain_id = "test-chain"
    return chain


def _agent(sift_text_decisions, chain) -> IRAgent:
    """IRAgent with mocked sift + ollama; sift_text_decisions[text] = recommendation."""
    sift = MagicMock()
    sift.check_dict.return_value = _scan("PASS", 0.0)

    def fake_check_text(text: str):
        rec = sift_text_decisions.get(text, "PASS")
        return _scan(rec, 0.85 if rec != "PASS" else 0.0)

    sift.check_text.side_effect = fake_check_text
    return IRAgent(sift=sift, chain=chain, ollama_client=MagicMock())


def test_boundary_blocks_ssrf_in_image_path(stub_chain):
    """The agent calls vol_pslist with an SSRF URL → boundary filter blocks."""
    agent = _agent(
        {"http://169.254.169.254/latest/meta-data": "BLOCK"},
        stub_chain,
    )
    output = agent._dispatch_tool(
        "vol_pslist",
        {"image_path": "http://169.254.169.254/latest/meta-data"},
    )
    parsed = json.loads(output)
    assert parsed["error"] == "blocked at agent->tool boundary"
    assert parsed["blocked_tool"] == "vol_pslist"
    assert parsed["blocked_arg"] == "image_path"
    # And a `blocked_tool_input` chain entry was appended
    appended_actions = [c.args[0] for c in stub_chain.append.call_args_list]
    assert "blocked_tool_input" in appended_actions


def test_boundary_blocks_on_flag_recommendation(stub_chain):
    """Stricter gating at the LLM->tool boundary: FLAG also blocks."""
    agent = _agent({"' OR 1=1 --": "FLAG"}, stub_chain)
    output = agent._dispatch_tool(
        "yara_match",
        {
            "rule_source": 'rule x { strings: $a = "abc" condition: $a }',
            "target_text": "' OR 1=1 --",
        },
    )
    parsed = json.loads(output)
    assert parsed.get("error") == "blocked at agent->tool boundary"


def test_boundary_does_not_block_pass(stub_chain):
    """Clean tool args pass straight through to the dispatch tree."""
    agent = _agent({}, stub_chain)
    # vol_pslist will fail with VolatilityFailed because the path doesn't
    # exist, but the boundary filter must NOT have blocked it.
    output = agent._dispatch_tool("vol_pslist", {"image_path": "/nonexistent/path"})
    parsed = json.loads(output)
    # Either dispatched (and got a tool error) or vol not installed —
    # critically, NOT a boundary block.
    assert parsed.get("error", "") != "blocked at agent->tool boundary"


def test_sift_classify_is_exempt_from_boundary(stub_chain):
    """sift_classify takes arbitrary text by design; never blocked at boundary."""
    agent = _agent({"http://169.254.169.254/latest/meta-data": "BLOCK"}, stub_chain)
    output = agent._dispatch_tool(
        "sift_classify",
        {"text": "http://169.254.169.254/latest/meta-data"},
    )
    parsed = json.loads(output)
    # Should successfully classify (not block at the dispatcher); the result
    # contains the recommendation field directly, not an error.
    assert "recommendation" in parsed
    assert parsed.get("error") != "blocked at agent->tool boundary"


def test_short_strings_skipped(stub_chain):
    """Args under 4 chars don't trigger the gate scan (false-positive guard)."""
    agent = _agent({}, stub_chain)
    output = agent._dispatch_tool("tsk_fls", {"image_path": "x", "offset": 0})
    parsed = json.loads(output)
    assert parsed.get("error", "") != "blocked at agent->tool boundary"
