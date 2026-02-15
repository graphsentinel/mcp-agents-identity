#!/bin/bash
set -euo pipefail

# MCPIdentity Benchmark Suite
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          MCPIdentity Benchmark Suite                          ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

OPA_URL="${OPA_URL:-http://localhost:8181}"
ITERATIONS="${ITERATIONS:-100}"

# Check OPA availability
if ! curl -s -o /dev/null -w "" "${OPA_URL}/health" 2>/dev/null; then
    echo -e "${RED}OPA not reachable at ${OPA_URL}${NC}"
    echo "Start port-forward: kubectl port-forward -n opa-system svc/opa 8181:8181"
    exit 1
fi

# Benchmark 1: OPA Policy Evaluation Latency
echo -e "${YELLOW}[1/3] OPA Policy Evaluation Latency (${ITERATIONS} iterations)${NC}"

declare -a latencies=()

for i in $(seq 1 "$ITERATIONS"); do
    start=$(date +%s%N)
    curl -s -o /dev/null -w "" -X POST "${OPA_URL}/v1/data/mcp/trust/allow" \
        -H "Content-Type: application/json" \
        -d '{"input":{"agent":{"trust_level":"trusted","svid_verified":true},"operation":"write","tool":"filesystem"}}'
    end=$(date +%s%N)
    latency_ms=$(( (end - start) / 1000000 ))
    latencies+=("$latency_ms")
done

# Calculate stats
IFS=$'\n' sorted=($(printf '%s\n' "${latencies[@]}" | sort -n)); unset IFS
count=${#sorted[@]}
sum=0
for l in "${sorted[@]}"; do sum=$((sum + l)); done
mean=$((sum / count))
p50=${sorted[$((count / 2))]}
p95=${sorted[$((count * 95 / 100))]}
p99=${sorted[$((count * 99 / 100))]}
min_val=${sorted[0]}
max_val=${sorted[$((count - 1))]}

echo "  Iterations: $count"
echo "  Min:  ${min_val}ms"
echo "  Mean: ${mean}ms"
echo "  P50:  ${p50}ms"
echo "  P95:  ${p95}ms"
echo "  P99:  ${p99}ms"
echo "  Max:  ${max_val}ms"
echo ""

# Benchmark 2: Concurrent Agent Count
echo -e "${YELLOW}[2/3] Active MCP Agents${NC}"
agent_count=$(kubectl get pods -n mcp-agents --field-selector=status.phase=Running -o name 2>/dev/null | wc -l || echo "0")
echo "  Running agents: $agent_count"
echo ""

# Benchmark 3: Credential Exposure Check
echo -e "${YELLOW}[3/3] Static Credential Exposure Check${NC}"
exposure_count=0
checked=0
for pod in $(kubectl get pods -n mcp-agents -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
    secrets=$(kubectl exec -n mcp-agents "$pod" -- sh -c 'env | grep -ciE "(API_KEY|SECRET|PASSWORD|STATIC_TOKEN)" || true' 2>/dev/null || echo "0")
    exposure_count=$((exposure_count + secrets))
    checked=$((checked + 1))
done
echo "  Agents checked: $checked"
echo "  Credential exposures: $exposure_count"
echo ""

# Summary
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          Benchmark Results                                    ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "| Metric | Result |"
echo "|--------|--------|"
echo "| Concurrent MCP Agents | $agent_count |"
echo "| Credential Exposures | $exposure_count |"
echo "| OPA Mean Auth Latency | ${mean}ms |"
echo "| OPA P50 Latency | ${p50}ms |"
echo "| OPA P95 Latency | ${p95}ms |"
echo "| OPA P99 Latency | ${p99}ms |"
