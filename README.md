# MCPIdentity PoC

> Zero Static Credentials for MCP Agents using SPIFFE + Keycloak + OPA

## Overview

This PoC demonstrates workload identity for MCP (Model Context Protocol) agents using:
- **SPIFFE/SPIRE 1.14** - Workload identity and JWT-SVID issuance
- **Keycloak 26.5** - OAuth2/OIDC with SPIFFE federation + DPoP
- **OPA** - Trust boundary and tool access policy enforcement
- **k3d** - Local Kubernetes cluster (1 server + 2 agents)

```
┌─────────────────────────────────────────────────────────────────┐
│                     MCPIdentity Architecture                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────┐       JWT-SVID        ┌──────────┐               │
│   │  SPIRE   │◄─────────────────────►│ Keycloak │               │
│   │  1.14.1  │                        │  26.5.3  │               │
│   └────┬─────┘                        └────┬─────┘               │
│        │                                   │                     │
│        │ Auto-rotated                      │ DPoP-bound          │
│        │ Identity (5 min)                  │ Bearer Token        │
│        ▼                                   ▼                     │
│   ┌──────────┐      Policy Query     ┌──────────┐               │
│   │   MCP    │──────────────────────►│   OPA    │               │
│   │  Agent   │                        │  Policy  │               │
│   └────┬─────┘                        └──────────┘               │
│        │                                                         │
│        │ Authenticated + Authorized                              │
│        ▼                                                         │
│   ┌──────────────────────────────────────────────────┐          │
│   │              MCP Tool Server                      │          │
│   │  (filesystem, database, api, shell, network)     │          │
│   └──────────────────────────────────────────────────┘          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Prerequisites

- k3d installed
- kubectl installed
- Docker running
- Python 3.11+ (for tests)

## Quick Start

```bash
# 1. Create k3d cluster
./scripts/01-create-cluster.sh

# 2. Deploy SPIRE
./scripts/02-deploy-spire.sh

# 3. Deploy Keycloak
./scripts/03-deploy-keycloak.sh

# 4. Deploy OPA
./scripts/04-deploy-opa.sh

# 5. Deploy MCP Agents (10 replicas: 4+3+3)
./scripts/05-deploy-mcp-agent.sh

# 6. Run Demo
./scripts/06-run-demo.sh
```

Or run all at once:
```bash
./scripts/setup-all.sh
```

## Directory Structure

```
mcp-identity-poc/
├── README.md                    # This file
├── pyproject.toml               # pytest configuration
├── requirements-test.txt        # Test dependencies
├── scripts/                     # Setup and demo scripts
│   ├── 01-create-cluster.sh     # k3d cluster creation
│   ├── 02-deploy-spire.sh       # SPIRE server & agent deployment
│   ├── 03-deploy-keycloak.sh    # Keycloak + realm import
│   ├── 04-deploy-opa.sh         # OPA deployment + policy load
│   ├── 05-deploy-mcp-agent.sh   # MCP agent deployment (3 tiers)
│   ├── 06-run-demo.sh           # 5-step demo (identity, OPA, token exchange)
│   ├── setup-all.sh             # Run all setup scripts
│   ├── benchmark.sh             # OPA latency + credential exposure benchmark
│   └── demo-video.sh            # Interactive asciinema recording script
├── manifests/                   # Kubernetes manifests
│   ├── spire/                   # SPIRE 1.14.1 server & agent
│   ├── keycloak/                # Keycloak 26.5.3 + mcp-realm.json
│   ├── opa/                     # OPA deployment + ConfigMap policies
│   └── mcp-agent/               # MCP agent (4+3+3 = 10 replicas)
├── policies/                    # OPA Rego policies
│   ├── trust-boundaries.rego    # Trust level + operation + tool enforcement
│   └── tool-access.rego         # Fine-grained tool action control
├── src/
│   └── mcp-agent/               # Python MCP agent
│       ├── Dockerfile           # Container image
│       ├── main.py              # FastAPI endpoints
│       ├── spiffe_client.py     # SPIFFE client (py-spiffe, fail-closed)
│       ├── opa_client.py        # OPA policy evaluation client (fail-closed)
│       ├── dpop_client.py       # DPoP proof-of-possession client (EC P-256)
│       ├── show_identity.py     # Identity display utility (fail-closed)
│       └── test_operation.py    # Operation test with OPA (fail-closed)
├── tests/                       # Automated test suite
│   ├── conftest.py              # Shared fixtures
│   ├── test_opa_policies.py     # OPA policy unit tests (opa eval CLI)
│   ├── test_spiffe_client.py    # SPIFFE client unit tests (fail-closed)
│   ├── test_dpop_client.py      # DPoP proof structure/crypto tests
│   └── test_main_api.py         # FastAPI endpoint tests
├── DEMO_SCENARIOS.md            # Step-by-step demo guide
└── presentation/                # Reveal.js slides
```

## Components

### 1. SPIRE (SPIFFE Runtime Environment) 1.14.1
- Issues JWT-SVIDs to workloads via Workload API
- Auto-rotates credentials (5 min default)
- Kubernetes workload attestation (`k8s_psat`)
- Trust domain: `mcp-identity.local`

### 2. Keycloak 26.5.3
- OAuth2/OIDC provider with `--features=preview` for SPIFFE support
- `client-jwt` authenticator with RS256 client assertion (RFC 7523)
- DPoP proof-of-possession token binding (ES256)
- Per-trust-level clients with SPIFFE ID protocol mapper

### 3. OPA (Open Policy Agent)
- Operation boundary enforcement (read/write/execute/admin)
- Tool access control (filesystem/database/api/shell/network)
- Policy-as-code (Rego)

### 4. MCP Agent
- Python-based demo agent (FastAPI)
- Uses SPIFFE identity via py-spiffe (no static credentials)
- Fail-closed: requires SPIRE + OPA to operate (no fallback)
- 3 trust tiers: trusted, semi-trusted, untrusted

## Trust Levels

### Operation Permissions

| Level | Operations |
|-------|-----------|
| **trusted** | read, write, execute, admin |
| **semi-trusted** | read, list |
| **untrusted** | read |

### Tool Access Matrix

| Tool | Trusted | Semi-trusted | Untrusted |
|------|---------|-------------|-----------|
| filesystem | yes | yes | yes |
| database | yes | yes | no |
| api | yes | yes | no |
| shell | yes | no | no |
| network | yes | no | no |

### Agent Replicas

| Level | Replicas |
|-------|----------|
| trusted | 4 |
| semi-trusted | 3 |
| untrusted | 3 |
| **Total** | **10** |

## Running Tests

```bash
pip install -r requirements-test.txt
pytest tests/ -v
```

## Benchmark

```bash
# Requires OPA port-forward: kubectl port-forward -n opa-system svc/opa 8181:8181
./scripts/benchmark.sh
```

## Demo Video

```bash
# Record with asciinema (8 steps, ENTER to advance)
asciinema rec --title "MCPIdentity PoC Demo" demo.cast
bash scripts/demo-video.sh
```

## License

Apache 2.0
