"""Shared test fixtures for MCPIdentity tests"""
import pytest
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'mcp-agent'))

TRUST_DOMAIN = "mcp-identity.local"
POLICIES_DIR = os.path.join(os.path.dirname(__file__), '..', 'policies')


@pytest.fixture
def trust_domain():
    return TRUST_DOMAIN


@pytest.fixture
def policies_dir():
    return POLICIES_DIR
