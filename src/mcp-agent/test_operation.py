#!/usr/bin/env python3
"""
Test operation against OPA policy.
Fail-closed: if OPA is unreachable, access is denied.
"""
import os
import sys
import json
import urllib.request

TRUST_DOMAIN = "mcp-identity.local"


def check_via_opa(trust_level, operation, tool="filesystem"):
    """Check via OPA endpoint. Raises on failure (fail-closed)."""
    opa_url = os.environ.get("OPA_URL", "http://opa.opa-system.svc.cluster.local:8181")

    input_data = {
        "input": {
            "agent": {
                "trust_level": trust_level,
                "svid_verified": True,
                "spiffe_id": f"spiffe://{TRUST_DOMAIN}/ns/mcp-agents/sa/mcp-agent-{trust_level}"
            },
            "operation": operation,
            "tool": tool,
            "sandbox_enabled": trust_level == "untrusted"
        }
    }

    req = urllib.request.Request(
        f"{opa_url}/v1/data/mcp/trust/allow",
        data=json.dumps(input_data).encode(),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=3) as resp:
        result = json.loads(resp.read())
        return result.get("result", False)


def main():
    if len(sys.argv) < 2:
        print("Usage: test_operation.py <operation> [tool]")
        sys.exit(1)

    operation = sys.argv[1]
    tool = sys.argv[2] if len(sys.argv) > 2 else "filesystem"
    trust_level = os.environ.get("TRUST_LEVEL", "untrusted")

    try:
        allowed = check_via_opa(trust_level, operation, tool)
        print("ALLOWED" if allowed else "DENIED")
        print(f"  (via OPA policy)")
    except Exception as e:
        print("DENIED")
        print(f"  (OPA unreachable — fail closed: {e})")
        sys.exit(1)


if __name__ == "__main__":
    main()
