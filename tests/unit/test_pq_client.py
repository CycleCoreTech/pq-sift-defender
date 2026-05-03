"""Unit tests for PQClient (mocked underlying SDK)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from pq_sift_defender.clients.pq_client import PQClient


def test_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CYCLECORE_PQ_API_KEY", raising=False)
    with pytest.raises(ValueError, match="API key required"):
        PQClient()


def test_picks_up_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CYCLECORE_PQ_API_KEY", "pq_live_test")
    with patch("pq_sift_defender.clients.pq_client.CycleCoreClient") as mock_client_cls:
        PQClient()
    mock_client_cls.assert_called_once()
    kwargs = mock_client_cls.call_args.kwargs
    assert kwargs["api_key"] == "pq_live_test"


def test_attest_delegates_to_sdk() -> None:
    with patch("pq_sift_defender.clients.pq_client.CycleCoreClient") as mock_client_cls:
        mock_instance = MagicMock()
        mock_client_cls.return_value = mock_instance
        client = PQClient(api_key="pq_live_test")
        client.attest({"action": "isolate", "host": "h1"}, chain_id="abc")
    mock_instance.attest.assert_called_once_with(
        data={"action": "isolate", "host": "h1"}, chain_id="abc"
    )


def test_attest_verify_delegates() -> None:
    with patch("pq_sift_defender.clients.pq_client.CycleCoreClient") as mock_client_cls:
        mock_instance = MagicMock()
        mock_client_cls.return_value = mock_instance
        client = PQClient(api_key="pq_live_test")
        client.attest_verify("chain-uuid")
    mock_instance.attest_verify.assert_called_once_with("chain-uuid")


def test_attest_export_delegates() -> None:
    with patch("pq_sift_defender.clients.pq_client.CycleCoreClient") as mock_client_cls:
        mock_instance = MagicMock()
        mock_client_cls.return_value = mock_instance
        client = PQClient(api_key="pq_live_test")
        client.attest_export("chain-uuid")
    mock_instance.attest_export.assert_called_once_with("chain-uuid")


def test_context_manager_closes() -> None:
    with patch("pq_sift_defender.clients.pq_client.CycleCoreClient") as mock_client_cls:
        mock_instance = MagicMock()
        mock_client_cls.return_value = mock_instance
        with PQClient(api_key="pq_live_test"):
            pass
    mock_instance.close.assert_called_once()
