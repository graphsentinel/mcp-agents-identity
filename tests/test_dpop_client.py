"""Unit tests for DPoP client"""
import pytest
import jwt

from dpop_client import DPoPClient


class TestDPoPClient:
    """Test DPoP proof-of-possession token generation"""

    def setup_method(self):
        self.client = DPoPClient("http://localhost:8080")

    def test_keypair_generated(self):
        """EC keypair should be generated on init"""
        assert self.client._private_key is not None
        assert self.client._public_key is not None

    def test_dpop_proof_structure(self):
        """DPoP proof should contain required claims"""
        proof = self.client._create_dpop_proof("POST", "http://localhost/token")
        decoded = jwt.decode(proof, options={"verify_signature": False})
        assert decoded["htm"] == "POST"
        assert decoded["htu"] == "http://localhost/token"
        assert "jti" in decoded
        assert "iat" in decoded

    def test_dpop_proof_header(self):
        """DPoP proof header should have correct typ and jwk"""
        proof = self.client._create_dpop_proof("GET", "http://example.com")
        header = jwt.get_unverified_header(proof)
        assert header["typ"] == "dpop+jwt"
        assert header["alg"] == "ES256"
        assert "jwk" in header
        assert header["jwk"]["kty"] == "EC"
        assert header["jwk"]["crv"] == "P-256"

    def test_dpop_proof_with_access_token_binding(self):
        """DPoP proof should include ath claim when binding to access token"""
        proof = self.client._create_dpop_proof(
            "GET", "http://example.com", access_token="some-access-token"
        )
        decoded = jwt.decode(proof, options={"verify_signature": False})
        assert "ath" in decoded

    def test_dpop_proof_without_access_token(self):
        """DPoP proof without access token should not have ath claim"""
        proof = self.client._create_dpop_proof("POST", "http://example.com")
        decoded = jwt.decode(proof, options={"verify_signature": False})
        assert "ath" not in decoded

    def test_jwk_thumbprint(self):
        """JWK thumbprint should be a non-empty base64url string"""
        thumbprint = self.client._get_jwk_thumbprint()
        assert isinstance(thumbprint, str)
        assert len(thumbprint) > 0

    def test_unique_jti_per_proof(self):
        """Each DPoP proof should have a unique jti"""
        proof1 = self.client._create_dpop_proof("POST", "http://example.com")
        proof2 = self.client._create_dpop_proof("POST", "http://example.com")
        jti1 = jwt.decode(proof1, options={"verify_signature": False})["jti"]
        jti2 = jwt.decode(proof2, options={"verify_signature": False})["jti"]
        assert jti1 != jti2

    def test_resource_proof_binds_token(self):
        """Resource proof should bind to access token"""
        proof = self.client.create_resource_proof(
            "my-access-token", "GET", "http://api.example.com/resource"
        )
        decoded = jwt.decode(proof, options={"verify_signature": False})
        assert decoded["htm"] == "GET"
        assert decoded["htu"] == "http://api.example.com/resource"
        assert "ath" in decoded
