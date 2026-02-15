#!/bin/bash
set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS_DIR="$SCRIPT_DIR/../manifests/spire"

echo -e "${GREEN}=== MCPIdentity PoC: Deploying SPIRE ===${NC}"

# Apply SPIRE CRDs and manifests
echo -e "${GREEN}Deploying SPIRE Server...${NC}"
kubectl apply -f "$MANIFESTS_DIR/spire-namespace.yaml"
kubectl apply -f "$MANIFESTS_DIR/spire-server-config.yaml"
kubectl apply -f "$MANIFESTS_DIR/spire-server.yaml"

# Wait for SPIRE Server
echo -e "${YELLOW}Waiting for SPIRE Server to be ready...${NC}"
kubectl wait --for=condition=ready pod -l app=spire-server -n spire-system --timeout=120s

echo -e "${GREEN}Deploying SPIRE Agent...${NC}"
kubectl apply -f "$MANIFESTS_DIR/spire-agent-config.yaml"
kubectl apply -f "$MANIFESTS_DIR/spire-agent.yaml"

# Wait for SPIRE Agent
echo -e "${YELLOW}Waiting for SPIRE Agent to be ready...${NC}"
kubectl wait --for=condition=ready pod -l app=spire-agent -n spire-system --timeout=120s

# Register workload entries for MCP agents
echo -e "${GREEN}Registering SPIFFE entries for MCP agents...${NC}"

# Get SPIRE Server pod
SPIRE_SERVER_POD=$(kubectl get pods -n spire-system -l app=spire-server -o jsonpath='{.items[0].metadata.name}')

# Register entries for different trust levels
kubectl exec -n spire-system "$SPIRE_SERVER_POD" -- \
    /opt/spire/bin/spire-server entry create \
    -spiffeID spiffe://mcp-identity.local/ns/mcp-agents/sa/mcp-agent-trusted \
    -parentID spiffe://mcp-identity.local/ns/spire-system/sa/spire-agent \
    -selector k8s:ns:mcp-agents \
    -selector k8s:sa:mcp-agent-trusted \
    -dns mcp-agent-trusted \
    -ttl 300 || true

kubectl exec -n spire-system "$SPIRE_SERVER_POD" -- \
    /opt/spire/bin/spire-server entry create \
    -spiffeID spiffe://mcp-identity.local/ns/mcp-agents/sa/mcp-agent-semi-trusted \
    -parentID spiffe://mcp-identity.local/ns/spire-system/sa/spire-agent \
    -selector k8s:ns:mcp-agents \
    -selector k8s:sa:mcp-agent-semi-trusted \
    -dns mcp-agent-semi-trusted \
    -ttl 300 || true

kubectl exec -n spire-system "$SPIRE_SERVER_POD" -- \
    /opt/spire/bin/spire-server entry create \
    -spiffeID spiffe://mcp-identity.local/ns/mcp-agents/sa/mcp-agent-untrusted \
    -parentID spiffe://mcp-identity.local/ns/spire-system/sa/spire-agent \
    -selector k8s:ns:mcp-agents \
    -selector k8s:sa:mcp-agent-untrusted \
    -dns mcp-agent-untrusted \
    -ttl 300 || true

echo -e "${GREEN}✓ SPIRE deployed successfully!${NC}"
echo ""
echo "SPIRE entries:"
kubectl exec -n spire-system "$SPIRE_SERVER_POD" -- \
    /opt/spire/bin/spire-server entry show
