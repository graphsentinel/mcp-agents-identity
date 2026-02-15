#!/bin/bash
# MCPIdentity PoC - Full Setup Script
# Bu script tüm demo ortamını sıfırdan kurar

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(dirname "$SCRIPT_DIR")"

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     MCPIdentity PoC - Full Setup                              ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo

cd "$POC_DIR"

# ============================================
# Step 1: Cluster Check/Create
# ============================================
echo -e "${YELLOW}[1/8] Checking k3d cluster...${NC}"

if k3d cluster list | grep -q "mcp-identity"; then
    echo -e "${GREEN}✓ Cluster 'mcp-identity' already exists${NC}"
else
    echo "Creating k3d cluster..."
    k3d cluster create mcp-identity --agents 2
    echo -e "${GREEN}✓ Cluster created${NC}"
fi

kubectl config use-context k3d-mcp-identity
echo

# ============================================
# Step 2: Namespaces
# ============================================
echo -e "${YELLOW}[2/8] Creating namespaces...${NC}"

kubectl create namespace spire-system --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace keycloak --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace opa-system --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace mcp-agents --dry-run=client -o yaml | kubectl apply -f -

echo -e "${GREEN}✓ Namespaces ready${NC}"
echo

# ============================================
# Step 3: SPIRE Setup
# ============================================
echo -e "${YELLOW}[3/8] Deploying SPIRE...${NC}"

# Bundle ConfigMap
kubectl create configmap spire-bundle -n spire-system --dry-run=client -o yaml | kubectl apply -f -

# SPIRE Server
kubectl apply -f manifests/spire/spire-server.yaml

echo "Waiting for SPIRE Server..."
kubectl wait --for=condition=Ready pod -l app=spire-server -n spire-system --timeout=120s || {
    echo -e "${RED}SPIRE Server failed to start. Check logs:${NC}"
    kubectl logs -n spire-system -l app=spire-server --tail=20
    exit 1
}

# SPIRE Agent
kubectl apply -f manifests/spire/spire-agent.yaml

echo "Waiting for SPIRE Agents..."
sleep 10
kubectl wait --for=condition=Ready pod -l app=spire-agent -n spire-system --timeout=120s || {
    echo -e "${RED}SPIRE Agents failed to start. Check logs:${NC}"
    kubectl logs -n spire-system -l app=spire-agent --tail=20
    exit 1
}

echo -e "${GREEN}✓ SPIRE deployed${NC}"
echo

# ============================================
# Step 4: SPIFFE Entries
# ============================================
echo -e "${YELLOW}[4/8] Registering SPIFFE entries...${NC}"

SPIRE_SERVER=$(kubectl get pods -n spire-system -l app=spire-server -o jsonpath='{.items[0].metadata.name}')
NODE_UID=$(kubectl get nodes -o jsonpath='{.items[0].metadata.uid}')
PARENT_ID="spiffe://mcp-identity.local/spire/agent/k8s_psat/mcp-identity/${NODE_UID}"

# Register entries (ignore if already exists)
for AGENT in trusted semi-trusted untrusted; do
    echo "  Registering mcp-agent-${AGENT}..."
    kubectl exec -n spire-system $SPIRE_SERVER -- /opt/spire/bin/spire-server entry create \
        -spiffeID "spiffe://mcp-identity.local/ns/mcp-agents/sa/mcp-agent-${AGENT}" \
        -parentID "$PARENT_ID" \
        -selector k8s:ns:mcp-agents \
        -selector "k8s:sa:mcp-agent-${AGENT}" 2>/dev/null || echo "    (may already exist)"
done

echo -e "${GREEN}✓ SPIFFE entries registered${NC}"
echo

# ============================================
# Step 5: OPA Setup
# ============================================
echo -e "${YELLOW}[5/8] Deploying OPA...${NC}"

# Policy ConfigMap
kubectl create configmap opa-policies \
    --from-file=policies/trust-boundaries.rego \
    -n opa-system \
    --dry-run=client -o yaml | kubectl apply -f -

# OPA Deployment
kubectl apply -f manifests/opa/opa-deployment.yaml

echo "Waiting for OPA..."
kubectl wait --for=condition=Ready pod -l app=opa -n opa-system --timeout=60s

echo -e "${GREEN}✓ OPA deployed${NC}"
echo

# ============================================
# Step 6: Keycloak Setup (Optional)
# ============================================
echo -e "${YELLOW}[6/8] Deploying Keycloak...${NC}"

kubectl apply -f manifests/keycloak/keycloak.yaml

echo "Waiting for Keycloak (this may take a while)..."
kubectl wait --for=condition=Ready pod -l app=keycloak -n keycloak --timeout=180s || {
    echo -e "${YELLOW}⚠ Keycloak still starting, continuing...${NC}"
}

echo -e "${GREEN}✓ Keycloak deployed${NC}"
echo

# ============================================
# Step 7: Build and Import MCP Agent Image
# ============================================
echo -e "${YELLOW}[7/8] Building MCP Agent image...${NC}"

cd src/mcp-agent
docker build -t mcp-agent:latest . 2>/dev/null || {
    echo -e "${YELLOW}⚠ Docker build failed, trying with podman...${NC}"
    podman build -t mcp-agent:latest .
}

k3d image import mcp-agent:latest -c mcp-identity
cd "$POC_DIR"

echo -e "${GREEN}✓ MCP Agent image ready${NC}"
echo

# ============================================
# Step 8: Deploy MCP Agents
# ============================================
echo -e "${YELLOW}[8/8] Deploying MCP Agents...${NC}"

# RBAC
kubectl apply -f manifests/mcp-agent/rbac.yaml

# Deployments
kubectl apply -f manifests/mcp-agent/mcp-agent-trusted.yaml
kubectl apply -f manifests/mcp-agent/mcp-agent-semi-trusted.yaml
kubectl apply -f manifests/mcp-agent/mcp-agent-untrusted.yaml

echo "Waiting for MCP Agents..."
sleep 5
kubectl wait --for=condition=Ready pod -l app.kubernetes.io/component=mcp-agent -n mcp-agents --timeout=60s || {
    echo -e "${YELLOW}⚠ Some agents still starting...${NC}"
}

echo -e "${GREEN}✓ MCP Agents deployed${NC}"
echo

# ============================================
# Summary
# ============================================
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     Setup Complete!                                           ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo

echo -e "${GREEN}Pod Status:${NC}"
kubectl get pods -A | grep -E "(spire|keycloak|opa|mcp)" | head -15
echo

echo -e "${YELLOW}Next Steps:${NC}"
echo "  1. Start OPA port-forward:"
echo "     kubectl port-forward -n opa-system svc/opa 8181:8181"
echo
echo "  2. Run SVID Demo:"
echo "     ./scripts/demo-svid-fetch.sh"
echo
echo "  3. Test Trust Boundaries:"
echo "     curl -s -X POST http://localhost:8181/v1/data/mcp/trust/allow \\"
echo "       -H 'Content-Type: application/json' \\"
echo "       -d '{\"input\":{\"agent\":{\"trust_level\":\"trusted\",\"svid_verified\":true},\"operation\":\"write\",\"tool\":\"filesystem\"}}' | jq ."
echo
echo -e "${GREEN}Keycloak Console: http://localhost:8180 (admin/admin)${NC}"
echo "  kubectl port-forward -n keycloak svc/keycloak 8180:8080"
