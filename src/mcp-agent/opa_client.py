"""
OPA Client for MCP Agent
Handles policy evaluation for trust boundaries
"""
import logging
from typing import Dict, Any
import httpx

logger = logging.getLogger(__name__)


class OPAClient:
    """
    Open Policy Agent client
    Evaluates trust boundary and tool access policies
    """

    def __init__(self, opa_url: str):
        self.opa_url = opa_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=5.0)

    async def check_access(
        self,
        agent_spiffe_id: str,
        trust_level: str,
        svid_verified: bool,
        tool: str,
        operation: str,
        sandbox_enabled: bool = False
    ) -> Dict[str, Any]:
        """
        Check if an operation is allowed by OPA policies

        Args:
            agent_spiffe_id: SPIFFE ID of the agent
            trust_level: Agent's trust level (trusted/semi-trusted/untrusted)
            svid_verified: Whether SVID has been verified
            tool: Tool name (filesystem, database, api, etc.)
            operation: Operation type (read, write, execute, etc.)
            sandbox_enabled: Whether sandbox is enabled

        Returns:
            Policy evaluation result
        """
        input_data = {
            "input": {
                "agent": {
                    "spiffe_id": agent_spiffe_id,
                    "trust_level": trust_level,
                    "svid_verified": svid_verified
                },
                "tool": tool,
                "operation": operation,
                "sandbox_enabled": sandbox_enabled
            }
        }

        try:
            response = await self._client.post(
                f"{self.opa_url}/v1/data/mcp/trust/response",
                json=input_data
            )
            response.raise_for_status()

            result = response.json()
            return result.get("result", {"allowed": False})

        except httpx.HTTPError as e:
            logger.error(f"OPA request failed: {e}")
            # Fail closed - deny access on error
            return {
                "allowed": False,
                "deny_reasons": [f"Policy evaluation failed: {str(e)}"]
            }

    async def check_tool_access(
        self,
        trust_level: str,
        tool: str,
        action: str,
        sandbox_enabled: bool = False
    ) -> Dict[str, Any]:
        """
        Check tool-specific access via tool-access policy

        Args:
            trust_level: Agent's trust level
            tool: Tool name
            action: Specific action (read, write, query, etc.)
            sandbox_enabled: Whether sandbox is enabled

        Returns:
            Tool access evaluation result
        """
        input_data = {
            "input": {
                "agent": {
                    "trust_level": trust_level,
                    "svid_verified": True
                },
                "tool": tool,
                "action": action,
                "sandbox_enabled": sandbox_enabled
            }
        }

        try:
            response = await self._client.post(
                f"{self.opa_url}/v1/data/mcp/tools/allow",
                json=input_data
            )
            response.raise_for_status()

            result = response.json()
            return {"allowed": result.get("result", False)}

        except httpx.HTTPError as e:
            logger.error(f"OPA tool access check failed: {e}")
            return {"allowed": False}

    async def get_available_tools(self, trust_level: str) -> list:
        """Get list of tools available for given trust level"""
        input_data = {
            "input": {
                "agent": {
                    "trust_level": trust_level,
                    "svid_verified": True
                }
            }
        }

        try:
            response = await self._client.post(
                f"{self.opa_url}/v1/data/mcp/tools/available_tools",
                json=input_data
            )
            response.raise_for_status()

            result = response.json()
            return list(result.get("result", []))

        except httpx.HTTPError as e:
            logger.error(f"Failed to get available tools: {e}")
            return []

    async def close(self):
        """Close HTTP client"""
        await self._client.aclose()
