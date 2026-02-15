"""
Test OPA policies without a running cluster.
Uses `opa eval` CLI to evaluate policies against test inputs.
Requires: opa binary installed (https://www.openpolicyagent.org/docs/latest/#running-opa)
"""
import json
import subprocess
import shutil
import pytest

OPA_BIN = shutil.which("opa")
pytestmark = pytest.mark.skipif(OPA_BIN is None, reason="opa binary not found in PATH")


def eval_trust_policy(input_data, policies_dir):
    """Evaluate trust boundary policy"""
    cmd = [
        OPA_BIN, "eval",
        "-d", policies_dir,
        "-i", "/dev/stdin",
        "data.mcp.trust.allow",
        "--format", "raw"
    ]
    result = subprocess.run(
        cmd, input=json.dumps(input_data), capture_output=True, text=True
    )
    return result.stdout.strip() == "true"


def eval_tool_policy(input_data, policies_dir):
    """Evaluate tool access policy"""
    cmd = [
        OPA_BIN, "eval",
        "-d", policies_dir,
        "-i", "/dev/stdin",
        "data.mcp.tools.allow",
        "--format", "raw"
    ]
    result = subprocess.run(
        cmd, input=json.dumps(input_data), capture_output=True, text=True
    )
    return result.stdout.strip() == "true"


class TestTrustBoundaryPolicy:
    """Tests for policies/trust-boundaries.rego"""

    def test_trusted_write_allowed(self, policies_dir):
        """Trusted agent with verified SVID can write to filesystem"""
        assert eval_trust_policy({
            "agent": {"trust_level": "trusted", "svid_verified": True},
            "operation": "write", "tool": "filesystem"
        }, policies_dir) is True

    def test_trusted_read_allowed(self, policies_dir):
        """Trusted agent can read"""
        assert eval_trust_policy({
            "agent": {"trust_level": "trusted", "svid_verified": True},
            "operation": "read", "tool": "filesystem"
        }, policies_dir) is True

    def test_trusted_execute_allowed(self, policies_dir):
        """Trusted agent can execute"""
        assert eval_trust_policy({
            "agent": {"trust_level": "trusted", "svid_verified": True},
            "operation": "execute", "tool": "shell"
        }, policies_dir) is True

    def test_trusted_admin_allowed(self, policies_dir):
        """Trusted agent has admin access"""
        assert eval_trust_policy({
            "agent": {"trust_level": "trusted", "svid_verified": True},
            "operation": "admin", "tool": "shell"
        }, policies_dir) is True

    def test_semi_trusted_read_allowed(self, policies_dir):
        """Semi-trusted agent can read"""
        assert eval_trust_policy({
            "agent": {"trust_level": "semi-trusted", "svid_verified": True},
            "operation": "read", "tool": "filesystem"
        }, policies_dir) is True

    def test_semi_trusted_write_denied(self, policies_dir):
        """Semi-trusted agent cannot write"""
        assert eval_trust_policy({
            "agent": {"trust_level": "semi-trusted", "svid_verified": True},
            "operation": "write", "tool": "filesystem"
        }, policies_dir) is False

    def test_semi_trusted_execute_denied(self, policies_dir):
        """Semi-trusted agent cannot execute"""
        assert eval_trust_policy({
            "agent": {"trust_level": "semi-trusted", "svid_verified": True},
            "operation": "execute", "tool": "shell"
        }, policies_dir) is False

    def test_untrusted_read_allowed(self, policies_dir):
        """Untrusted agent can read filesystem"""
        assert eval_trust_policy({
            "agent": {"trust_level": "untrusted", "svid_verified": True},
            "operation": "read", "tool": "filesystem"
        }, policies_dir) is True

    def test_untrusted_write_denied(self, policies_dir):
        """Untrusted agent cannot write"""
        assert eval_trust_policy({
            "agent": {"trust_level": "untrusted", "svid_verified": True},
            "operation": "write", "tool": "filesystem"
        }, policies_dir) is False

    def test_unverified_svid_always_denied(self, policies_dir):
        """Unverified SVID is denied even for trusted agent"""
        assert eval_trust_policy({
            "agent": {"trust_level": "trusted", "svid_verified": False},
            "operation": "read", "tool": "filesystem"
        }, policies_dir) is False

    def test_unverified_svid_admin_denied(self, policies_dir):
        """Spoofed trust level without SVID is denied"""
        assert eval_trust_policy({
            "agent": {"trust_level": "trusted", "svid_verified": False},
            "operation": "admin", "tool": "shell"
        }, policies_dir) is False

    def test_semi_trusted_database_allowed(self, policies_dir):
        """Semi-trusted can access database tool"""
        assert eval_trust_policy({
            "agent": {"trust_level": "semi-trusted", "svid_verified": True},
            "operation": "read", "tool": "database"
        }, policies_dir) is True

    def test_untrusted_database_denied(self, policies_dir):
        """Untrusted cannot access database tool"""
        assert eval_trust_policy({
            "agent": {"trust_level": "untrusted", "svid_verified": True},
            "operation": "read", "tool": "database"
        }, policies_dir) is False

    def test_untrusted_shell_denied(self, policies_dir):
        """Untrusted cannot access shell tool"""
        assert eval_trust_policy({
            "agent": {"trust_level": "untrusted", "svid_verified": True},
            "operation": "read", "tool": "shell"
        }, policies_dir) is False


class TestToolAccessPolicy:
    """Tests for policies/tool-access.rego"""

    def test_trusted_shell_with_sandbox(self, policies_dir):
        """Trusted can execute shell with sandbox enabled"""
        assert eval_tool_policy({
            "agent": {"trust_level": "trusted", "svid_verified": True},
            "tool": "shell", "action": "execute", "sandbox_enabled": True
        }, policies_dir) is True

    def test_trusted_shell_without_sandbox(self, policies_dir):
        """Shell execute requires sandbox even for trusted"""
        assert eval_tool_policy({
            "agent": {"trust_level": "trusted", "svid_verified": True},
            "tool": "shell", "action": "execute", "sandbox_enabled": False
        }, policies_dir) is False

    def test_untrusted_filesystem_read(self, policies_dir):
        """Untrusted can read filesystem"""
        assert eval_tool_policy({
            "agent": {"trust_level": "untrusted", "svid_verified": True},
            "tool": "filesystem", "action": "read", "sandbox_enabled": False
        }, policies_dir) is True

    def test_untrusted_filesystem_write_denied(self, policies_dir):
        """Untrusted cannot write filesystem"""
        assert eval_tool_policy({
            "agent": {"trust_level": "untrusted", "svid_verified": True},
            "tool": "filesystem", "action": "write", "sandbox_enabled": False
        }, policies_dir) is False

    def test_untrusted_database_denied(self, policies_dir):
        """Untrusted cannot query database"""
        assert eval_tool_policy({
            "agent": {"trust_level": "untrusted", "svid_verified": True},
            "tool": "database", "action": "query", "sandbox_enabled": False
        }, policies_dir) is False

    def test_semi_trusted_database_query(self, policies_dir):
        """Semi-trusted can query database"""
        assert eval_tool_policy({
            "agent": {"trust_level": "semi-trusted", "svid_verified": True},
            "tool": "database", "action": "query", "sandbox_enabled": False
        }, policies_dir) is True

    def test_semi_trusted_database_insert_denied(self, policies_dir):
        """Semi-trusted cannot insert to database"""
        assert eval_tool_policy({
            "agent": {"trust_level": "semi-trusted", "svid_verified": True},
            "tool": "database", "action": "insert", "sandbox_enabled": False
        }, policies_dir) is False

    def test_semi_trusted_api_get(self, policies_dir):
        """Semi-trusted can GET API"""
        assert eval_tool_policy({
            "agent": {"trust_level": "semi-trusted", "svid_verified": True},
            "tool": "api", "action": "get", "sandbox_enabled": False
        }, policies_dir) is True

    def test_unverified_svid_tool_denied(self, policies_dir):
        """Unverified SVID blocks all tool access"""
        assert eval_tool_policy({
            "agent": {"trust_level": "trusted", "svid_verified": False},
            "tool": "filesystem", "action": "read", "sandbox_enabled": False
        }, policies_dir) is False

    def test_network_listen_requires_sandbox(self, policies_dir):
        """Network listen requires sandbox"""
        assert eval_tool_policy({
            "agent": {"trust_level": "trusted", "svid_verified": True},
            "tool": "network", "action": "listen", "sandbox_enabled": True
        }, policies_dir) is True

        assert eval_tool_policy({
            "agent": {"trust_level": "trusted", "svid_verified": True},
            "tool": "network", "action": "listen", "sandbox_enabled": False
        }, policies_dir) is False
