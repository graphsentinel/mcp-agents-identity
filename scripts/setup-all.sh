#!/bin/bash
set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          MCPIdentity PoC - Full Setup                         ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}✗ $1 is not installed${NC}"
        exit 1
    else
        echo -e "${GREEN}✓ $1 found${NC}"
    fi
}

check_command k3d
check_command kubectl
check_command docker

# Check Docker is running
if ! docker info &> /dev/null; then
    echo -e "${RED}✗ Docker is not running${NC}"
    exit 1
else
    echo -e "${GREEN}✓ Docker is running${NC}"
fi

echo ""

# Run all setup scripts
STEPS=(
    "01-create-cluster.sh:Creating k3d cluster"
    "02-deploy-spire.sh:Deploying SPIRE"
    "03-deploy-keycloak.sh:Deploying Keycloak"
    "04-deploy-opa.sh:Deploying OPA"
    "05-deploy-mcp-agent.sh:Deploying MCP Agents"
)

for step in "${STEPS[@]}"; do
    script="${step%%:*}"
    description="${step##*:}"

    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}Step: $description${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    if bash "$SCRIPT_DIR/$script"; then
        echo -e "${GREEN}✓ $description completed${NC}"
    else
        echo -e "${RED}✗ $description failed${NC}"
        exit 1
    fi

    echo ""
done

echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          Setup Complete!                                       ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Next steps:"
echo "  1. Run the demo: ./scripts/06-run-demo.sh"
echo "  2. Access Keycloak: http://localhost:8180 (admin/admin)"
echo "  3. View agents: kubectl get pods -n mcp-agents"
echo ""
echo "To cleanup:"
echo "  k3d cluster delete mcp-identity"
