#!/bin/bash
set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS_DIR="$SCRIPT_DIR/../manifests/opa"
POLICIES_DIR="$SCRIPT_DIR/../policies"

echo -e "${GREEN}=== MCPIdentity PoC: Deploying OPA ===${NC}"

# Deploy OPA
echo -e "${GREEN}Deploying OPA...${NC}"
kubectl apply -f "$MANIFESTS_DIR/opa-deployment.yaml"

# Wait for OPA
echo -e "${YELLOW}Waiting for OPA to be ready...${NC}"
kubectl wait --for=condition=ready pod -l app=opa -n opa-system --timeout=120s

# Create ConfigMap with policies
echo -e "${GREEN}Loading trust boundary policies...${NC}"
kubectl create configmap mcp-policies \
    --from-file="$POLICIES_DIR/trust-boundaries.rego" \
    --from-file="$POLICIES_DIR/tool-access.rego" \
    -n opa-system \
    --dry-run=client -o yaml | kubectl apply -f -

# Restart OPA to pick up policies
kubectl rollout restart deployment/opa -n opa-system
kubectl wait --for=condition=ready pod -l app=opa -n opa-system --timeout=60s

echo -e "${GREEN}✓ OPA deployed successfully!${NC}"
echo ""
echo "OPA endpoint: http://opa.opa-system.svc.cluster.local:8181"

# Test policy
echo -e "${GREEN}Testing OPA policy...${NC}"
OPA_POD=$(kubectl get pods -n opa-system -l app=opa -o jsonpath='{.items[0].metadata.name}')

kubectl exec -n opa-system "$OPA_POD" -- \
    wget -q -O- --post-data='{"input":{"agent":{"trust_level":"trusted","svid_verified":true},"operation":"write","tool":"filesystem"}}' \
    http://localhost:8181/v1/data/mcp/trust/allow || echo "Policy test completed"
