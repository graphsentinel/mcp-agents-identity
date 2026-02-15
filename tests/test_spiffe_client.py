"""Unit tests for SpiffeClient (fail-closed — no fallback)"""
import sys
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta
from types import ModuleType

# Import from src
from spiffe_client import SpiffeClient, SVID, TRUST_DOMAIN


def _create_spiffe_module(workload_client_class):
    """Create a fake 'spiffe' module with a given WorkloadApiClient class."""
    mod = ModuleType("spiffe")
    mod.WorkloadApiClient = workload_client_class
    return mod


class TestSVIDDataclass:
    """Test SVID data structure"""

    def test_svid_fields(self):
        svid = SVID(
            spiffe_id="spiffe://mcp-identity.local/ns/mcp-agents/sa/mcp-agent-trusted",
            token="eyJhbGci.test.token",
            expiry=datetime.now(timezone.utc) + timedelta(minutes=5),
            is_real=True,
        )
        assert "mcp-identity.local" in svid.spiffe_id
        assert svid.is_real is True
        assert svid.token.startswith("eyJ")

    def test_trust_domain_constant(self):
        assert TRUST_DOMAIN == "mcp-identity.local"


class TestSpiffeClientFailClosed:
    """Test SPIFFE client fail-closed behavior"""

    def _mock_unavailable_client(self):
        """Create a WorkloadApiClient mock where fetch always fails (SPIRE down)."""
        mock_client = MagicMock()
        mock_client.fetch_jwt_svid.side_effect = Exception("connection refused")
        mock_client.close.return_value = None
        return mock_client

    @pytest.mark.asyncio
    async def test_no_spire_returns_none(self):
        """Without SPIRE, get_svid() must return None (fail-closed)"""
        mock_client = self._mock_unavailable_client()
        factory = MagicMock(return_value=mock_client)
        fake_mod = _create_spiffe_module(factory)
        with patch.dict(sys.modules, {"spiffe": fake_mod}):
            client = SpiffeClient("unix:///nonexistent/socket")
            await client.start()
            svid = await client.get_svid()
            assert svid is None
            await client.stop()

    @pytest.mark.asyncio
    async def test_no_spire_is_not_connected(self):
        """Without SPIRE, is_real_mode must be False"""
        mock_client = self._mock_unavailable_client()
        factory = MagicMock(return_value=mock_client)
        fake_mod = _create_spiffe_module(factory)
        with patch.dict(sys.modules, {"spiffe": fake_mod}):
            client = SpiffeClient("unix:///nonexistent/socket")
            await client.start()
            assert client.is_real_mode is False
            await client.stop()

    @pytest.mark.asyncio
    async def test_no_spire_jwt_token_returns_none(self):
        """Without SPIRE, get_jwt_token() must return None"""
        mock_client = self._mock_unavailable_client()
        factory = MagicMock(return_value=mock_client)
        fake_mod = _create_spiffe_module(factory)
        with patch.dict(sys.modules, {"spiffe": fake_mod}):
            client = SpiffeClient("unix:///nonexistent/socket")
            await client.start()
            token = await client.get_jwt_token()
            assert token is None
            await client.stop()


class TestSpiffeClientConnected:
    """Test SPIFFE client when SPIRE is available (mocked)"""

    def _mock_workload_client(self):
        mock_svid = MagicMock()
        mock_svid.spiffe_id = "spiffe://mcp-identity.local/ns/mcp-agents/sa/mcp-agent-trusted"
        mock_svid.token = "eyJhbGciOiJFUzI1NiJ9.test.signature"
        mock_svid.expiry = int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp())

        mock_client = MagicMock()
        mock_client.fetch_jwt_svid.return_value = mock_svid
        mock_client.close.return_value = None
        return mock_client

    @pytest.mark.asyncio
    async def test_connected_returns_real_svid(self):
        """With SPIRE, get_svid() returns a real SVID"""
        mock_client = self._mock_workload_client()
        factory = MagicMock(return_value=mock_client)
        fake_mod = _create_spiffe_module(factory)
        with patch.dict(sys.modules, {"spiffe": fake_mod}):
            client = SpiffeClient("unix:///run/spire/sockets/agent.sock")
            await client.start()
            assert client.is_real_mode is True
            svid = await client.get_svid()
            assert svid is not None
            assert svid.is_real is True
            assert "mcp-agent-trusted" in svid.spiffe_id
            await client.stop()

    @pytest.mark.asyncio
    async def test_connected_jwt_token(self):
        """With SPIRE, get_jwt_token() returns token string"""
        mock_client = self._mock_workload_client()
        factory = MagicMock(return_value=mock_client)
        fake_mod = _create_spiffe_module(factory)
        with patch.dict(sys.modules, {"spiffe": fake_mod}):
            client = SpiffeClient("unix:///run/spire/sockets/agent.sock")
            await client.start()
            token = await client.get_jwt_token()
            assert token is not None
            assert token.startswith("eyJ")
            await client.stop()

    @pytest.mark.asyncio
    async def test_svid_expiry_is_utc(self):
        """SVID expiry should be timezone-aware UTC"""
        mock_client = self._mock_workload_client()
        factory = MagicMock(return_value=mock_client)
        fake_mod = _create_spiffe_module(factory)
        with patch.dict(sys.modules, {"spiffe": fake_mod}):
            client = SpiffeClient("unix:///run/spire/sockets/agent.sock")
            await client.start()
            svid = await client.get_svid()
            assert svid.expiry.tzinfo is not None
            assert svid.expiry > datetime.now(timezone.utc)
            await client.stop()

    @pytest.mark.asyncio
    async def test_fetch_failure_returns_none(self):
        """If SPIRE fetch fails after connection, returns None (no fallback)"""
        mock_client = self._mock_workload_client()
        factory = MagicMock(return_value=mock_client)
        fake_mod = _create_spiffe_module(factory)
        with patch.dict(sys.modules, {"spiffe": fake_mod}):
            client = SpiffeClient("unix:///run/spire/sockets/agent.sock")
            await client.start()
            assert client.is_real_mode is True

            # Now make subsequent fetches fail
            mock_client.fetch_jwt_svid.side_effect = Exception("SPIRE unavailable")
            # Clear cached SVID to force re-fetch
            client._current_svid = None
            svid = await client.get_svid()
            assert svid is None  # fail-closed, no demo fallback
            await client.stop()
