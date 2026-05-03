"""Unit tests for IRChain (mocked PQClient)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pq_sift_defender.audit.chain import IRChain


def _attest_result(chain_id: str = "c1", entry_index: int = 0, entry_hash: str = "h0") -> MagicMock:
    r = MagicMock()
    r.chain_id = chain_id
    r.entry_index = entry_index
    r.entry_hash = entry_hash
    return r


def test_first_append_creates_chain() -> None:
    pq = MagicMock()
    pq.attest.return_value = _attest_result(chain_id="c1", entry_index=0)
    chain = IRChain(pq=pq)
    assert chain.chain_id is None
    chain.append("isolate", {"host": "h1"})
    assert chain.chain_id == "c1"
    assert chain.length == 1


def test_subsequent_append_reuses_chain_id() -> None:
    pq = MagicMock()
    pq.attest.side_effect = [
        _attest_result(chain_id="c1", entry_index=0, entry_hash="h0"),
        _attest_result(chain_id="c1", entry_index=1, entry_hash="h1"),
    ]
    chain = IRChain(pq=pq)
    chain.append("isolate", {"host": "h1"})
    chain.append("scan", {"target": "h1"})
    assert chain.chain_id == "c1"
    assert chain.length == 2
    second_call_kwargs = pq.attest.call_args_list[1].kwargs
    assert second_call_kwargs["chain_id"] == "c1"


def test_verify_requires_started_chain() -> None:
    pq = MagicMock()
    chain = IRChain(pq=pq)
    with pytest.raises(RuntimeError, match="Chain not started"):
        chain.verify()


def test_export_requires_started_chain() -> None:
    pq = MagicMock()
    chain = IRChain(pq=pq)
    with pytest.raises(RuntimeError, match="Chain not started"):
        chain.export()


def test_verify_delegates_to_pq() -> None:
    pq = MagicMock()
    pq.attest.return_value = _attest_result()
    chain = IRChain(pq=pq)
    chain.append("init", {})
    chain.verify()
    pq.attest_verify.assert_called_once_with("c1")
