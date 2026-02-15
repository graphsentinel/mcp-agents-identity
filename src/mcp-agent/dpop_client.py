"""
DPoP Client for MCP Agent
Implements Demonstrating Proof of Possession (DPoP) tokens
"""
import logging
import time
import uuid
import hashlib
import base64
from typing import Optional, Dict, Any
import httpx
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class DPoPClient:
    """
    DPoP Token Client
    Creates proof-of-possession tokens to prevent credential theft
    """

    def __init__(self, keycloak_url: str):
        self.keycloak_url = keycloak_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=10.0)
        self._private_key = None
        self._public_key = None
        self._generate_keypair()

    def _generate_keypair(self):
        """Generate EC keypair for DPoP proofs"""
        self._private_key = ec.generate_private_key(
            ec.SECP256R1(),
            default_backend()
        )
        self._public_key = self._private_key.public_key()
        logger.info("Generated new DPoP keypair")

    def _get_jwk_thumbprint(self) -> str:
        """Calculate JWK thumbprint for the public key"""
        # Get public key numbers
        numbers = self._public_key.public_numbers()

        # Create JWK
        jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": base64.urlsafe_b64encode(
                numbers.x.to_bytes(32, byteorder='big')
            ).decode().rstrip('='),
            "y": base64.urlsafe_b64encode(
                numbers.y.to_bytes(32, byteorder='big')
            ).decode().rstrip('=')
        }

        # Calculate thumbprint (SHA-256 of canonical JWK)
        import json
        canonical = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
        thumbprint = hashlib.sha256(canonical.encode()).digest()

        return base64.urlsafe_b64encode(thumbprint).decode().rstrip('=')

    def _create_dpop_proof(
        self,
        http_method: str,
        http_uri: str,
        access_token: Optional[str] = None
    ) -> str:
        """
        Create DPoP proof JWT

        Args:
            http_method: HTTP method (GET, POST, etc.)
            http_uri: Target URI
            access_token: Optional access token to bind

        Returns:
            DPoP proof JWT
        """
        now = int(time.time())

        # Get public key numbers for JWK
        numbers = self._public_key.public_numbers()

        header = {
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": base64.urlsafe_b64encode(
                    numbers.x.to_bytes(32, byteorder='big')
                ).decode().rstrip('='),
                "y": base64.urlsafe_b64encode(
                    numbers.y.to_bytes(32, byteorder='big')
                ).decode().rstrip('=')
            }
        }

        payload = {
            "jti": str(uuid.uuid4()),
            "htm": http_method,
            "htu": http_uri,
            "iat": now
        }

        # If binding to access token, include ath claim
        if access_token:
            token_hash = hashlib.sha256(access_token.encode()).digest()
            payload["ath"] = base64.urlsafe_b64encode(token_hash).decode().rstrip('=')

        # Sign with private key
        proof = jwt.encode(
            payload,
            self._private_key,
            algorithm="ES256",
            headers=header
        )

        return proof

    async def get_token(
        self,
        svid,
        tool: str,
        operation: str
    ) -> Optional[str]:
        """
        Get DPoP-bound access token from Keycloak

        Args:
            svid: SPIFFE SVID
            tool: Tool being accessed
            operation: Operation being performed

        Returns:
            DPoP-bound access token
        """
        token_url = f"{self.keycloak_url}/realms/mcp-identity/protocol/openid-connect/token"

        # Create DPoP proof for token endpoint
        dpop_proof = self._create_dpop_proof("POST", token_url)

        try:
            # Request token using SPIFFE JWT as client assertion
            response = await self._client.post(
                token_url,
                headers={
                    "DPoP": dpop_proof,
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                data={
                    "grant_type": "client_credentials",
                    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    "client_assertion": svid.token,
                    "scope": f"mcp-tools tool:{tool} operation:{operation}"
                }
            )

            if response.status_code == 200:
                token_response = response.json()
                access_token = token_response.get("access_token")
                logger.info(f"Obtained DPoP-bound token for {tool}/{operation}")
                return access_token
            else:
                logger.warning(f"Token request failed: {response.status_code}")
                return None

        except httpx.HTTPError as e:
            logger.error(f"Token request error: {e}")
            return None

    def create_resource_proof(
        self,
        access_token: str,
        http_method: str,
        resource_uri: str
    ) -> str:
        """
        Create DPoP proof for resource access

        Args:
            access_token: The DPoP-bound access token
            http_method: HTTP method for resource request
            resource_uri: Resource URI being accessed

        Returns:
            DPoP proof JWT
        """
        return self._create_dpop_proof(
            http_method,
            resource_uri,
            access_token
        )

    async def close(self):
        """Close HTTP client"""
        await self._client.aclose()
