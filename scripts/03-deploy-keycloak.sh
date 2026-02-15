#!/bin/bash
set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS_DIR="$SCRIPT_DIR/../manifests/keycloak"

echo -e "${GREEN}=== MCPIdentity PoC: Deploying Keycloak ===${NC}"

# Deploy Keycloak
echo -e "${GREEN}Deploying Keycloak...${NC}"
kubectl apply -f "$MANIFESTS_DIR/keycloak-deployment.yaml"

# Wait for Keycloak
echo -e "${YELLOW}Waiting for Keycloak to be ready (this may take a few minutes)...${NC}"
kubectl wait --for=condition=ready pod -l app=keycloak -n keycloak --timeout=300s

# Get Keycloak pod
KEYCLOAK_POD=$(kubectl get pods -n keycloak -l app=keycloak -o jsonpath='{.items[0].metadata.name}')

# Wait for Keycloak to be fully initialized
echo -e "${YELLOW}Waiting for Keycloak to fully initialize...${NC}"
sleep 30

# Import realm configuration
echo -e "${GREEN}Configuring Keycloak realm for MCP Identity...${NC}"

# Authenticate kcadm
kubectl exec -n keycloak "$KEYCLOAK_POD" -- \
    /opt/keycloak/bin/kcadm.sh config credentials \
    --server http://localhost:8080 \
    --realm master \
    --user admin \
    --password admin || true

# Import realm via stdin pipe (Keycloak 26.5.3 image has no tar, so kubectl cp fails)
kubectl exec -i -n keycloak "$KEYCLOAK_POD" -- \
    /opt/keycloak/bin/kcadm.sh create realms \
    -f - < "$MANIFESTS_DIR/mcp-realm.json" || true

echo -e "${GREEN}✓ Keycloak deployed successfully!${NC}"
echo ""
echo "Keycloak URL: http://localhost:8080/keycloak"
echo "Admin Console: http://localhost:8080/keycloak/admin"
echo "Credentials: admin / admin"
echo ""
echo "MCP Realm: mcp-identity"

# Port forward for local access
echo -e "${YELLOW}Starting port-forward (Ctrl+C to stop)...${NC}"
echo "Access Keycloak at: http://localhost:8180"
kubectl port-forward -n keycloak svc/keycloak 8180:8080 &
