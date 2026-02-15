"""Tests for MCPIdentity FastAPI endpoints"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'mcp-agent'))


@pytest.fixture
def mock_svid():
    """Create a mock SVID"""
    from spiffe_client import SVID
    return SVID(
        spiffe_id="spiffe://mcp-identity.local/ns/mcp-agents/sa/mcp-agent-trusted",
        token="mock-jwt-token",
        expiry=datetime.now() + timedelta(hours=1),
        hint="trusted",
        is_real=False,
    )


@pytest.fixture
def app_client(mock_svid):
    """Create a test client with mocked dependencies"""
    from httpx import ASGITransport, AsyncClient

    # Patch environment before importing main
    with patch.dict(os.environ, {
        "TRUST_LEVEL": "trusted",
        "AGENT_NAME": "test-agent",
        "OPA_URL": "http://localhost:8181",
        "KEYCLOAK_URL": "http://localhost:8080",
    }):
        # Mock the clients before importing main
        mock_spiffe = AsyncMock()
        mock_spiffe.get_svid = AsyncMock(return_value=mock_svid)
        mock_spiffe.is_real_mode = False
        mock_spiffe.start = AsyncMock()
        mock_spiffe.stop = AsyncMock()

        mock_opa = AsyncMock()
        mock_dpop = AsyncMock()

        with patch("main.SpiffeClient", return_value=mock_spiffe), \
             patch("main.OPAClient", return_value=mock_opa), \
             patch("main.DPoPClient", return_value=mock_dpop):

            # Force reimport to pick up patches
            if "main" in sys.modules:
                del sys.modules["main"]
            import main

            main.spiffe_client = mock_spiffe
            main.opa_client = mock_opa
            main.dpop_client = mock_dpop

            transport = ASGITransport(app=main.app)
            client = AsyncClient(transport=transport, base_url="http://test")
            yield client, mock_spiffe, mock_opa, mock_dpop


class TestHealthEndpoint:
    """Test /health endpoint"""

    @pytest.mark.asyncio
    async def test_health_returns_ok(self, app_client):
        client, mock_spiffe, _, _ = app_client
        async with client:
            response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["agent_name"] == "test-agent"
        assert data["trust_level"] == "trusted"

    @pytest.mark.asyncio
    async def test_health_shows_spiffe_mode(self, app_client):
        client, mock_spiffe, _, _ = app_client
        async with client:
            response = await client.get("/health")
        data = response.json()
        assert "spiffe_mode" in data
        assert data["spiffe_mode"] in ("real", "demo")


class TestIdentityEndpoint:
    """Test /identity endpoint"""

    @pytest.mark.asyncio
    async def test_identity_returns_spiffe_id(self, app_client, mock_svid):
        client, mock_spiffe, _, _ = app_client
        async with client:
            response = await client.get("/identity")
        assert response.status_code == 200
        data = response.json()
        assert data["spiffe_id"] == mock_svid.spiffe_id
        assert data["trust_level"] == "trusted"
        assert data["agent_name"] == "test-agent"

    @pytest.mark.asyncio
    async def test_identity_includes_expiry(self, app_client):
        client, _, _, _ = app_client
        async with client:
            response = await client.get("/identity")
        data = response.json()
        assert data["svid_expiry"] is not None


class TestCheckAccessEndpoint:
    """Test /check-access endpoint"""

    @pytest.mark.asyncio
    async def test_check_access_allowed(self, app_client):
        client, _, mock_opa, _ = app_client
        mock_opa.check_access = AsyncMock(return_value={
            "allowed": True,
            "deny_reasons": [],
        })
        async with client:
            response = await client.post(
                "/check-access?tool=filesystem&operation=read"
            )
        assert response.status_code == 200
        data = response.json()
        assert data["allowed"] is True
        assert data["tool"] == "filesystem"
        assert data["operation"] == "read"

    @pytest.mark.asyncio
    async def test_check_access_denied(self, app_client):
        client, _, mock_opa, _ = app_client
        mock_opa.check_access = AsyncMock(return_value={
            "allowed": False,
            "deny_reasons": ["operation not permitted for trust level"],
        })
        async with client:
            response = await client.post(
                "/check-access?tool=shell&operation=execute"
            )
        assert response.status_code == 200
        data = response.json()
        assert data["allowed"] is False
        assert len(data["deny_reasons"]) > 0

    @pytest.mark.asyncio
    async def test_check_access_no_svid_returns_401(self, app_client):
        client, mock_spiffe, _, _ = app_client
        mock_spiffe.get_svid = AsyncMock(return_value=None)
        async with client:
            response = await client.post(
                "/check-access?tool=filesystem&operation=read"
            )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_check_access_passes_svid_verified(self, app_client, mock_svid):
        client, _, mock_opa, _ = app_client
        mock_opa.check_access = AsyncMock(return_value={"allowed": True})
        async with client:
            await client.post("/check-access?tool=filesystem&operation=read")
        mock_opa.check_access.assert_called_once()
        call_kwargs = mock_opa.check_access.call_args
        assert call_kwargs.kwargs.get("svid_verified") == mock_svid.is_real or \
               call_kwargs[1].get("svid_verified") == mock_svid.is_real


class TestExecuteToolEndpoint:
    """Test /execute-tool endpoint"""

    @pytest.mark.asyncio
    async def test_execute_allowed_tool(self, app_client):
        client, _, mock_opa, mock_dpop = app_client
        mock_opa.check_access = AsyncMock(return_value={
            "allowed": True,
            "deny_reasons": [],
        })
        mock_dpop.get_token = AsyncMock(return_value="dpop-bound-token")
        async with client:
            response = await client.post(
                "/execute-tool?tool=filesystem&operation=read",
                json={"path": "/tmp/test"},
            )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "executed"
        assert data["token_bound"] is True

    @pytest.mark.asyncio
    async def test_execute_denied_tool_returns_403(self, app_client):
        client, _, mock_opa, _ = app_client
        mock_opa.check_access = AsyncMock(return_value={
            "allowed": False,
            "deny_reasons": ["access denied by policy"],
        })
        async with client:
            response = await client.post(
                "/execute-tool?tool=shell&operation=execute",
                json={},
            )
        assert response.status_code == 403
