#!/usr/bin/env python3
"""
Show current SPIFFE identity from SPIRE.
Fail-closed: if SPIRE is unavailable, reports error (no fallback ID).
"""
import os
import sys


def main():
    trust_level = os.environ.get("TRUST_LEVEL", "unknown")
    agent_name = os.environ.get("AGENT_NAME", "unknown")
    spiffe_socket = os.environ.get("SPIFFE_ENDPOINT_SOCKET", "not set")

    spiffe_id = None
    error = None
    try:
        from spiffe import WorkloadApiClient
        socket = spiffe_socket
        if socket.startswith("unix://"):
            socket = socket[len("unix://"):]
        client = WorkloadApiClient(socket_path=f"unix://{socket}")
        jwt_svid = client.fetch_jwt_svid(audience={"mcp-identity"})
        spiffe_id = str(jwt_svid.spiffe_id)
    except Exception as e:
        error = str(e)

    print(f"  Agent Name: {agent_name}")
    print(f"  Trust Level: {trust_level}")
    if spiffe_id:
        print(f"  SPIFFE ID: {spiffe_id}")
        print(f"  SPIFFE Socket: {spiffe_socket}")
        print(f"  Mode: REAL (SPIRE)")
        print(f"  Static Credentials: None (using SPIFFE SVID)")
    else:
        print(f"  SPIFFE ID: UNAVAILABLE")
        print(f"  Mode: ERROR — SPIRE unreachable ({error})")
        print(f"  Static Credentials: None (agent has no identity)")
        sys.exit(1)


if __name__ == "__main__":
    main()
