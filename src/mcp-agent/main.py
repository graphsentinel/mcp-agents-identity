"""
MCPIdentity Demo Agent
Demonstrates SPIFFE-based workload identity for MCP agents
"""
import os
import asyncio
import logging
from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager

from spiffe_client import SpiffeClient
from opa_client import OPAClient
from dpop_client import DPoPClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration from environment
TRUST_LEVEL = os.environ.get("TRUST_LEVEL", "untrusted")
SPIFFE_SOCKET = os.environ.get("SPIFFE_ENDPOINT_SOCKET", "unix:///run/spire/sockets/agent.sock")
OPA_URL = os.environ.get("OPA_URL", "http://opa.opa-system.svc.cluster.local:8181")
KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak.keycloak.svc.cluster.local:8080")
AGENT_NAME = os.environ.get("AGENT_NAME", "mcp-agent")

# Global clients
spiffe_client: SpiffeClient = None
opa_client: OPAClient = None
dpop_client: DPoPClient = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler"""
    global spiffe_client, opa_client, dpop_client

    logger.info(f"Starting MCP Agent: {AGENT_NAME}")
    logger.info(f"Trust Level: {TRUST_LEVEL}")

    # Initialize clients
    spiffe_client = SpiffeClient(SPIFFE_SOCKET)
    opa_client = OPAClient(OPA_URL)
    dpop_client = DPoPClient(KEYCLOAK_URL)

    # Start SVID watcher
    await spiffe_client.start()

    logger.info("MCP Agent initialized successfully")

    yield

    # Cleanup
    await spiffe_client.stop()
    logger.info("MCP Agent shutdown complete")


app = FastAPI(
    title="MCPIdentity Demo Agent",
    description="Demonstrates SPIFFE-based workload identity",
    lifespan=lifespan
)


@app.get("/health")
async def health():
    """Health check endpoint — reports degraded if SPIRE is unavailable"""
    spire_connected = spiffe_client and spiffe_client.is_real_mode
    return {
        "status": "healthy" if spire_connected else "degraded",
        "agent_name": AGENT_NAME,
        "trust_level": TRUST_LEVEL,
        "spiffe_mode": "spire" if spire_connected else "unavailable"
    }


@app.get("/identity")
async def get_identity():
    """Get current SPIFFE identity"""
    svid = await spiffe_client.get_svid()
    return {
        "spiffe_id": svid.spiffe_id if svid else None,
        "trust_level": TRUST_LEVEL,
        "svid_expiry": svid.expiry.isoformat() if svid else None,
        "agent_name": AGENT_NAME
    }


@app.post("/check-access")
async def check_access(tool: str, operation: str):
    """Check if operation is allowed via OPA"""
    svid = await spiffe_client.get_svid()

    if not svid:
        raise HTTPException(status_code=401, detail="No valid SVID")

    result = await opa_client.check_access(
        agent_spiffe_id=svid.spiffe_id,
        trust_level=TRUST_LEVEL,
        svid_verified=svid.is_real,
        tool=tool,
        operation=operation
    )

    return {
        "allowed": result.get("allowed", False),
        "trust_level": TRUST_LEVEL,
        "tool": tool,
        "operation": operation,
        "deny_reasons": result.get("deny_reasons", [])
    }


@app.post("/execute-tool")
async def execute_tool(tool: str, operation: str, params: dict = None):
    """Execute a tool operation with policy enforcement"""
    # First check access
    access = await check_access(tool, operation)

    if not access["allowed"]:
        raise HTTPException(
            status_code=403,
            detail=f"Access denied: {access['deny_reasons']}"
        )

    # Get DPoP token for the operation
    svid = await spiffe_client.get_svid()
    token = await dpop_client.get_token(svid, tool, operation)

    # Simulate tool execution
    result = {
        "tool": tool,
        "operation": operation,
        "params": params,
        "status": "executed",
        "token_bound": token is not None
    }

    logger.info(f"Tool executed: {tool}/{operation} by {TRUST_LEVEL} agent")

    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
