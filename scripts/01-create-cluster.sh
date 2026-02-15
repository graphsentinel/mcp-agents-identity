#!/bin/bash
set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== MCPIdentity PoC: Creating k3d Cluster ===${NC}"

CLUSTER_NAME="mcp-identity"

# Check if cluster already exists
if k3d cluster list | grep -q "$CLUSTER_NAME"; then
    echo -e "${YELLOW}Cluster '$CLUSTER_NAME' already exists.${NC}"
    read -p "Delete and recreate? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Deleting existing cluster..."
        k3d cluster delete "$CLUSTER_NAME"
    else
        echo "Using existing cluster."
        kubectl config use-context "k3d-$CLUSTER_NAME"
        exit 0
    fi
fi

# Create k3d cluster with specific configuration
echo -e "${GREEN}Creating k3d cluster: $CLUSTER_NAME${NC}"

k3d cluster create "$CLUSTER_NAME" \
    --servers 1 \
    --agents 2 \
    --port "8080:80@loadbalancer" \
    --port "8443:443@loadbalancer" \
    --port "9000:9000@loadbalancer" \
    --k3s-arg "--disable=traefik@server:0" \
    --wait

# Verify cluster
echo -e "${GREEN}Verifying cluster...${NC}"
kubectl cluster-info
kubectl get nodes

# Create namespaces
echo -e "${GREEN}Creating namespaces...${NC}"
kubectl create namespace spire-system --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace keycloak --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace opa-system --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace mcp-agents --dry-run=client -o yaml | kubectl apply -f -

# Label namespaces
kubectl label namespace mcp-agents mcp-identity=enabled --overwrite

echo -e "${GREEN}✓ Cluster '$CLUSTER_NAME' created successfully!${NC}"
echo ""
echo "Namespaces created:"
kubectl get namespaces | grep -E "spire|keycloak|opa|mcp"
