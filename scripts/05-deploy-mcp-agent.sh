#!/bin/bash
set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS_DIR="$SCRIPT_DIR/../manifests/mcp-agent"

echo -e "${GREEN}=== MCPIdentity PoC: Deploying MCP Agents ===${NC}"

# Build MCP Agent image
echo -e "${GREEN}Building MCP Agent image...${NC}"
docker build -t mcp-agent:latest "$SCRIPT_DIR/../src/mcp-agent"

# Import image to k3d
echo -e "${GREEN}Importing image to k3d cluster...${NC}"
k3d image import mcp-agent:latest -c mcp-identity

# Deploy service accounts
echo -e "${GREEN}Creating service accounts for different trust levels...${NC}"
kubectl apply -f "$MANIFESTS_DIR/service-accounts.yaml"

# Deploy MCP agents
echo -e "${GREEN}Deploying MCP agents...${NC}"
kubectl apply -f "$MANIFESTS_DIR/mcp-agent-trusted.yaml"
kubectl apply -f "$MANIFESTS_DIR/mcp-agent-semi-trusted.yaml"
kubectl apply -f "$MANIFESTS_DIR/mcp-agent-untrusted.yaml"

# Wait for agents
echo -e "${YELLOW}Waiting for MCP agents to be ready...${NC}"
kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=mcp-agent -n mcp-agents --timeout=120s

echo -e "${GREEN}✓ MCP Agents deployed successfully!${NC}"
echo ""
echo "Deployed agents:"
kubectl get pods -n mcp-agents -l app.kubernetes.io/component=mcp-agent

echo ""
echo "Trust levels:"
echo "  - mcp-agent-trusted: Full access"
echo "  - mcp-agent-semi-trusted: Limited access"
echo "  - mcp-agent-untrusted: Read-only sandboxed"
