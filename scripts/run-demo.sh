#!/bin/bash
# MCPIdentity PoC - Interactive Demo Runner
# Sunumda kullanmak için interaktif demo

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

# OPA URL check
OPA_URL="${OPA_URL:-http://localhost:8181}"

pause() {
    echo
    echo -e "${CYAN}[Enter'a basın devam etmek için...]${NC}"
    read -r
}

header() {
    clear
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     MCPIdentity Demo - $1${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo
}

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

if ! kubectl get pods -n opa-system -l app=opa 2>/dev/null | grep -q Running; then
    echo -e "${RED}Error: OPA is not running${NC}"
    echo "Run: kubectl apply -f manifests/opa/opa-deployment.yaml"
    exit 1
fi

if ! curl -s "$OPA_URL/health" > /dev/null 2>&1; then
    echo -e "${RED}Error: Cannot reach OPA at $OPA_URL${NC}"
    echo "Run: kubectl port-forward -n opa-system svc/opa 8181:8181"
    exit 1
fi

echo -e "${GREEN}✓ Prerequisites OK${NC}"
pause

# ============================================
# Demo 1: Zero Static Credentials
# ============================================
header "Zero Static Credentials"

echo -e "${YELLOW}Problem:${NC} Traditional apps use hardcoded API keys, secrets"
echo -e "${GREEN}Solution:${NC} SPIFFE provides dynamic, auto-rotating identities"
echo
echo -e "${CYAN}Let's check what credentials our agents have...${NC}"
pause

echo -e "${YELLOW}Trusted Agent - Searching for secrets:${NC}"
echo "$ kubectl exec -n mcp-agents deployment/mcp-agent-trusted -- env | grep -E '(KEY|SECRET|PASSWORD)'"
kubectl exec -n mcp-agents deployment/mcp-agent-trusted -- env 2>/dev/null | grep -E "(KEY|SECRET|PASSWORD|CREDENTIAL)" || echo -e "${GREEN}   ✓ No static credentials found!${NC}"
echo

echo -e "${YELLOW}Instead, agents use SPIFFE socket:${NC}"
echo "$ kubectl exec -n mcp-agents deployment/mcp-agent-trusted -- env | grep SPIFFE"
kubectl exec -n mcp-agents deployment/mcp-agent-trusted -- env 2>/dev/null | grep SPIFFE
echo

echo -e "${GREEN}Key Insight:${NC} Identity comes from SPIRE, not config files"
pause

# ============================================
# Demo 2: SPIFFE Identity System
# ============================================
header "SPIFFE Identity System"

echo -e "${YELLOW}What is SPIFFE?${NC}"
echo "  • Secure Production Identity Framework for Everyone"
echo "  • Every workload gets a unique cryptographic identity"
echo "  • Format: spiffe://trust-domain/path"
echo
echo -e "${CYAN}Let's see registered identities...${NC}"
pause

SPIRE_SERVER=$(kubectl get pods -n spire-system -l app=spire-server -o jsonpath='{.items[0].metadata.name}')

echo -e "${YELLOW}SPIRE Server Health:${NC}"
kubectl exec -n spire-system $SPIRE_SERVER -- /opt/spire/bin/spire-server healthcheck 2>/dev/null
echo

echo -e "${YELLOW}Registered SPIFFE Entries:${NC}"
kubectl exec -n spire-system $SPIRE_SERVER -- /opt/spire/bin/spire-server entry show 2>/dev/null | head -40
echo

echo -e "${GREEN}Each agent has a unique SPIFFE ID based on:${NC}"
echo "  • Namespace (mcp-agents)"
echo "  • ServiceAccount (mcp-agent-trusted, etc.)"
pause

# ============================================
# Demo 3: Trust Boundary Enforcement
# ============================================
header "Trust Boundary Enforcement"

echo -e "${YELLOW}Trust Levels:${NC}"
echo "  🟢 trusted      → read, write, execute, admin"
echo "  🟡 semi-trusted → read, list only"
echo "  🔴 untrusted    → read only"
echo
echo -e "${CYAN}OPA enforces these boundaries in real-time...${NC}"
pause

test_policy() {
    local trust=$1
    local op=$2
    local tool=$3
    local expected=$4

    result=$(curl -s -X POST "$OPA_URL/v1/data/mcp/trust/allow" \
        -H "Content-Type: application/json" \
        -d "{\"input\":{\"agent\":{\"trust_level\":\"$trust\",\"svid_verified\":true},\"operation\":\"$op\",\"tool\":\"$tool\"}}")

    allowed=$(echo $result | grep -o '"result":[^}]*' | cut -d: -f2)

    if [ "$allowed" == "$expected" ]; then
        icon="✓"
        color=$GREEN
    else
        icon="✗"
        color=$RED
    fi

    printf "  %-15s + %-8s + %-12s = ${color}%-6s ${icon}${NC}\n" "$trust" "$op" "$tool" "$allowed"
}

echo -e "${YELLOW}Testing Policy Decisions:${NC}"
echo
echo "  Agent           Operation  Tool          Result"
echo "  ─────────────── ───────── ────────────── ──────"

test_policy "trusted" "write" "filesystem" "true"
test_policy "trusted" "admin" "shell" "true"
test_policy "semi-trusted" "write" "filesystem" "false"
test_policy "semi-trusted" "read" "filesystem" "true"
test_policy "untrusted" "read" "filesystem" "true"
test_policy "untrusted" "write" "filesystem" "false"
test_policy "untrusted" "read" "database" "false"

echo
echo -e "${GREEN}Key Insight:${NC} Same request, different results based on identity"
pause

# ============================================
# Demo 4: SVID Verification (Attack Prevention)
# ============================================
header "SVID Verification - Attack Prevention"

echo -e "${YELLOW}Attack Scenario:${NC}"
echo "  What if an attacker spoofs trust_level='trusted'?"
echo "  Without cryptographic verification, policy is useless!"
echo
echo -e "${CYAN}Let's simulate an attack...${NC}"
pause

echo -e "${YELLOW}Legitimate Request (SVID verified):${NC}"
echo '  {"agent":{"trust_level":"trusted","svid_verified":true},"operation":"admin","tool":"shell"}'
result=$(curl -s -X POST "$OPA_URL/v1/data/mcp/trust/allow" \
    -H "Content-Type: application/json" \
    -d '{"input":{"agent":{"trust_level":"trusted","svid_verified":true},"operation":"admin","tool":"shell"}}')
echo -e "  Result: ${GREEN}$(echo $result | jq -r .result)${NC}"
echo

echo -e "${RED}Attack Attempt (no SVID):${NC}"
echo '  {"agent":{"trust_level":"trusted","svid_verified":false},"operation":"admin","tool":"shell"}'
result=$(curl -s -X POST "$OPA_URL/v1/data/mcp/trust/allow" \
    -H "Content-Type: application/json" \
    -d '{"input":{"agent":{"trust_level":"trusted","svid_verified":false},"operation":"admin","tool":"shell"}}')
echo -e "  Result: ${RED}$(echo $result | jq -r .result) ← Blocked!${NC}"
echo

echo -e "${GREEN}Defense in Depth:${NC}"
echo "  • SPIFFE provides cryptographic identity"
echo "  • OPA verifies SVID before allowing operations"
echo "  • Attackers can't just set trust_level in config"
pause

# ============================================
# Demo 5: Tool Access Control
# ============================================
header "Tool Access Control"

echo -e "${YELLOW}Different tools have different risk levels:${NC}"
echo "  • filesystem - Low risk (read files)"
echo "  • database   - Medium risk (data access)"
echo "  • shell      - High risk (command execution)"
echo "  • network    - High risk (external connections)"
echo
echo -e "${CYAN}Policy restricts tool access by trust level...${NC}"
pause

echo -e "${YELLOW}Tool Access Matrix:${NC}"
echo
echo "  Tool        Trusted   Semi-trusted   Untrusted"
echo "  ────────── ───────── ────────────── ──────────"

for tool in filesystem database api shell network; do
    printf "  %-10s" "$tool"
    for trust in trusted semi-trusted untrusted; do
        result=$(curl -s -X POST "$OPA_URL/v1/data/mcp/trust/allow" \
            -H "Content-Type: application/json" \
            -d "{\"input\":{\"agent\":{\"trust_level\":\"$trust\",\"svid_verified\":true},\"operation\":\"read\",\"tool\":\"$tool\"}}" | grep -o '"result":[^}]*' | cut -d: -f2)

        if [ "$result" == "true" ]; then
            printf " ${GREEN}   ✓${NC}       "
        else
            printf " ${RED}   ✗${NC}       "
        fi
    done
    echo
done

echo
echo -e "${GREEN}Key Insight:${NC} Least privilege per agent type"
pause

# ============================================
# Summary
# ============================================
header "Summary"

echo -e "${GREEN}MCPIdentity Security Architecture:${NC}"
echo
echo "  ┌─────────────────────────────────────────────────────┐"
echo "  │                    MCP Agent                        │"
echo "  │  ┌───────────┐    ┌───────────┐    ┌───────────┐   │"
echo "  │  │  Trusted  │    │Semi-Trust │    │ Untrusted │   │"
echo "  │  └─────┬─────┘    └─────┬─────┘    └─────┬─────┘   │"
echo "  └────────┼────────────────┼────────────────┼─────────┘"
echo "           │                │                │"
echo "           └────────────────┼────────────────┘"
echo "                            │"
echo "                   ┌────────▼────────┐"
echo "                   │  SPIFFE/SPIRE   │ ← Cryptographic Identity"
echo "                   └────────┬────────┘"
echo "                            │"
echo "                   ┌────────▼────────┐"
echo "                   │       OPA       │ ← Policy Enforcement"
echo "                   └────────┬────────┘"
echo "                            │"
echo "                   ┌────────▼────────┐"
echo "                   │    Keycloak     │ ← Token Federation"
echo "                   └─────────────────┘"
echo
echo -e "${YELLOW}Key Benefits:${NC}"
echo "  ✓ Zero static credentials"
echo "  ✓ Cryptographic workload identity"
echo "  ✓ Trust boundary enforcement"
echo "  ✓ Defense against privilege escalation"
echo "  ✓ Audit trail via OPA decisions"
echo
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     Demo Complete - Questions?                                ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
