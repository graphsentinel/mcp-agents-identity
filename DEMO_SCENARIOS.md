# MCPIdentity Demo Scenarios

> Demo senaryoları ve komutları - Open Source Summit 2026

---

## 🎯 Adım Adım Demo Rehberi

Bu rehber, MCPIdentity PoC'yi sıfırdan kurup demo yapmak için gereken tüm adımları içerir.

### Adım 1: Cluster Oluşturma

```bash
# k3d cluster oluştur
k3d cluster create mcp-identity --agents 2

# Cluster'a bağlan
kubectl cluster-info
```

### Adım 2: Namespace'leri Oluştur

```bash
# Tüm namespace'leri oluştur
kubectl create namespace spire-system
kubectl create namespace keycloak
kubectl create namespace opa-system
kubectl create namespace mcp-agents
```

### Adım 3: SPIRE Kurulumu

```bash
# PoC dizinine git
cd Docs/md/detailed/rfp-combined/oss-summit-2026/digital-trust/mcp-identity-poc

# SPIRE bundle ConfigMap (SPIRE server başlamadan önce gerekli)
kubectl create configmap spire-bundle -n spire-system

# SPIRE Server deploy
kubectl apply -f manifests/spire/spire-server.yaml

# SPIRE Server'ın hazır olmasını bekle
kubectl wait --for=condition=Ready pod -l app=spire-server -n spire-system --timeout=120s

# SPIRE Agent deploy
kubectl apply -f manifests/spire/spire-agent.yaml

# Agent'ların hazır olmasını bekle
kubectl wait --for=condition=Ready pod -l app=spire-agent -n spire-system --timeout=120s
```

### Adım 4: SPIFFE Entry'leri Kaydet

```bash
# SPIRE Server pod adını al
SPIRE_SERVER=$(kubectl get pods -n spire-system -l app=spire-server -o jsonpath='{.items[0].metadata.name}')

# Trusted Agent entry
kubectl exec -n spire-system $SPIRE_SERVER -- /opt/spire/bin/spire-server entry create \
  -spiffeID spiffe://mcp-identity.local/ns/mcp-agents/sa/mcp-agent-trusted \
  -parentID spiffe://mcp-identity.local/spire/agent/k8s_psat/mcp-identity/$(kubectl get nodes -o jsonpath='{.items[0].metadata.uid}') \
  -selector k8s:ns:mcp-agents \
  -selector k8s:sa:mcp-agent-trusted

# Semi-Trusted Agent entry
kubectl exec -n spire-system $SPIRE_SERVER -- /opt/spire/bin/spire-server entry create \
  -spiffeID spiffe://mcp-identity.local/ns/mcp-agents/sa/mcp-agent-semi-trusted \
  -parentID spiffe://mcp-identity.local/spire/agent/k8s_psat/mcp-identity/$(kubectl get nodes -o jsonpath='{.items[0].metadata.uid}') \
  -selector k8s:ns:mcp-agents \
  -selector k8s:sa:mcp-agent-semi-trusted

# Untrusted Agent entry
kubectl exec -n spire-system $SPIRE_SERVER -- /opt/spire/bin/spire-server entry create \
  -spiffeID spiffe://mcp-identity.local/ns/mcp-agents/sa/mcp-agent-untrusted \
  -parentID spiffe://mcp-identity.local/spire/agent/k8s_psat/mcp-identity/$(kubectl get nodes -o jsonpath='{.items[0].metadata.uid}') \
  -selector k8s:ns:mcp-agents \
  -selector k8s:sa:mcp-agent-untrusted

# Entry'leri doğrula
kubectl exec -n spire-system $SPIRE_SERVER -- /opt/spire/bin/spire-server entry show
```

### Adım 5: OPA Kurulumu

```bash
# OPA Policy ConfigMap
kubectl create configmap opa-policies \
  --from-file=policies/trust-boundaries.rego \
  -n opa-system

# OPA Deployment
kubectl apply -f manifests/opa/opa-deployment.yaml

# OPA'nın hazır olmasını bekle
kubectl wait --for=condition=Ready pod -l app=opa -n opa-system --timeout=60s

# OPA health check
kubectl port-forward -n opa-system svc/opa 8181:8181 &
sleep 2
curl -s http://localhost:8181/health | jq .
```

### Adım 6: Keycloak Kurulumu (Opsiyonel)

```bash
# Keycloak deploy
kubectl apply -f manifests/keycloak/keycloak.yaml

# Keycloak'ın hazır olmasını bekle (biraz zaman alabilir)
kubectl wait --for=condition=Ready pod -l app=keycloak -n keycloak --timeout=180s

# Keycloak'a erişim
kubectl port-forward -n keycloak svc/keycloak 8180:8080 &
echo "Keycloak: http://localhost:8180 (admin/admin)"
```

### Adım 7: MCP Agent'ları Deploy Et

```bash
# Agent image build (Docker)
cd src/mcp-agent
docker build -t mcp-agent:latest .
k3d image import mcp-agent:latest -c mcp-identity
cd ../..

# ServiceAccount'ları oluştur
kubectl apply -f manifests/mcp-agent/rbac.yaml

# Agent deployment'ları
kubectl apply -f manifests/mcp-agent/mcp-agent-trusted.yaml
kubectl apply -f manifests/mcp-agent/mcp-agent-semi-trusted.yaml
kubectl apply -f manifests/mcp-agent/mcp-agent-untrusted.yaml

# Agent'ların hazır olmasını bekle
kubectl wait --for=condition=Ready pod -l app.kubernetes.io/component=mcp-agent -n mcp-agents --timeout=60s
```

### Adım 8: Kurulumu Doğrula

```bash
# Tüm pod'ları kontrol et
echo "=== Tüm Pod'lar ==="
kubectl get pods -A | grep -E "(spire|keycloak|opa|mcp)"

# Beklenen: Tüm pod'lar "Running" durumunda
```

### Adım 9: Demo'yu Çalıştır

```bash
# Terminal 1: OPA port-forward (açık değilse)
kubectl port-forward -n opa-system svc/opa 8181:8181

# Terminal 2: Demo script
chmod +x scripts/demo-svid-fetch.sh
./scripts/demo-svid-fetch.sh

# Veya manuel senaryoları çalıştır (aşağıdaki senaryolara bakın)
```

---

## 📋 Hızlı Başlangıç (Cluster Hazırsa)

Cluster zaten kuruluysa, sadece port-forward ve demo:

```bash
# 1. Cluster'a bağlan
kubectl config use-context k3d-mcp-identity

# 2. Pod durumunu kontrol et
kubectl get pods -A | grep -E "(spire|keycloak|opa|mcp)"

# 3. Port-forward'ları başlat
kubectl port-forward -n opa-system svc/opa 8181:8181 &
kubectl port-forward -n keycloak svc/keycloak 8180:8080 &

# 4. SVID Demo
./scripts/demo-svid-fetch.sh

# 5. Keycloak Token Exchange Demo (via JWT client assertion)
# In production, agents use SPIFFE JWT-SVID as client_assertion
# For demo, use Keycloak service account with client-jwt auth
curl -s -X POST http://localhost:8180/realms/mcp-identity/protocol/openid-connect/token \
  -d "grant_type=client_credentials" \
  -d "client_id=mcp-agent-trusted" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=<JWT_SVID>" | jq '{token_type, expires_in}'

# 6. Trust Boundary Demo (OPA testi)
curl -s -X POST http://localhost:8181/v1/data/mcp/trust/allow \
  -H "Content-Type: application/json" \
  -d '{"input":{"agent":{"trust_level":"trusted","svid_verified":true},"operation":"write","tool":"filesystem"}}' | jq .
```

---

## 🎬 Sunum Sırası Önerisi (Prezentasyon ile Senkron)

1. **Giriş** (2 dk): Problem tanımı - MCP agent'lar güvenilir mi?
2. **Demo 1 → Senaryo 1** (3 dk): Zero Static Credentials - Hiç hardcoded secret yok
3. **Demo 2 → Senaryo 9** (4 dk): SPIFFE SVID Demo - Identity nasıl çalışıyor
4. **Demo 3 → Senaryo 3** (5 dk): Keycloak Token Exchange - SVID → DPoP-bound token
5. **Demo 4 → Senaryo 2** (4 dk): Trust Boundary - OPA policy enforcement
6. **Demo 5 → Senaryo 5** (3 dk): SVID Verification - Spoofing koruması
7. **Demo 6 → Senaryo 4** (2 dk): Tool Access Matrix - Least privilege
8. **Kapanış** (2 dk): Sonuçlar ve Q&A

> **Toplam:** ~25 dakika (40 dk session için ideal, 15 dk Q&A kalır)

---

## Ön Hazırlık

### Cluster Durumu Kontrolü

```bash
# Tüm pod'ları kontrol et
kubectl get pods -A | grep -E "(spire|keycloak|opa|mcp)"

# Beklenen çıktı:
# keycloak       keycloak-xxx                      1/1     Running
# mcp-agents     mcp-agent-semi-trusted-xxx        1/1     Running
# mcp-agents     mcp-agent-trusted-xxx             1/1     Running
# mcp-agents     mcp-agent-untrusted-xxx           1/1     Running
# opa-system     opa-xxx                           1/1     Running
# spire-system   spire-agent-xxx                   1/1     Running
# spire-system   spire-agent-xxx                   1/1     Running
# spire-system   spire-agent-xxx                   1/1     Running
# spire-system   spire-server-0                    1/1     Running
```

### Port Forward Başlat

```bash
# Terminal 1: OPA
kubectl port-forward -n opa-system svc/opa 8181:8181

# Terminal 2: Keycloak (opsiyonel)
kubectl port-forward -n keycloak svc/keycloak 8180:8080
```

---

## Senaryo 1: Zero Static Credentials

**Amaç:** Agent'ların static credential kullanmadığını göster

### Komutlar

```bash
echo "=== Senaryo 1: Zero Static Credentials ==="
echo ""

echo "1. Trusted Agent - Environment Variables:"
kubectl exec -n mcp-agents deployment/mcp-agent-trusted -- env | grep -E "(KEY|SECRET|PASSWORD|TOKEN|CREDENTIAL)" || echo "   Hiç static credential yok!"
echo ""

echo "2. Trusted Agent - Trust Level ve SPIFFE Socket:"
kubectl exec -n mcp-agents deployment/mcp-agent-trusted -- env | grep -E "(TRUST|SPIFFE)"
echo ""

echo "3. Semi-Trusted Agent:"
kubectl exec -n mcp-agents deployment/mcp-agent-semi-trusted -- env | grep -E "(TRUST|SPIFFE)"
echo ""

echo "4. Untrusted Agent:"
kubectl exec -n mcp-agents deployment/mcp-agent-untrusted -- env | grep -E "(TRUST|SPIFFE)"
```

### Beklenen Çıktı

```
=== Senaryo 1: Zero Static Credentials ===

1. Trusted Agent - Environment Variables:
   Hiç static credential yok!

2. Trusted Agent - Trust Level ve SPIFFE Socket:
TRUST_LEVEL=trusted
SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/sockets/agent.sock

3. Semi-Trusted Agent:
TRUST_LEVEL=semi-trusted
SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/sockets/agent.sock

4. Untrusted Agent:
TRUST_LEVEL=untrusted
SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/sockets/agent.sock
```

### Açıklama

- Hiçbir agent'ta `API_KEY`, `SECRET`, `PASSWORD` gibi değişkenler yok
- Her agent sadece `TRUST_LEVEL` ve `SPIFFE_ENDPOINT_SOCKET` kullanıyor
- Identity, SPIFFE üzerinden otomatik sağlanıyor

---

## Senaryo 2: Trust Boundary Enforcement

**Amaç:** Farklı trust level'ların farklı yetkilere sahip olduğunu göster

### Komutlar

```bash
echo "=== Senaryo 2: Trust Boundary Enforcement ==="
echo ""

echo "1. TRUSTED agent - WRITE işlemi (ALLOWED olmalı):"
curl -s -X POST http://localhost:8181/v1/data/mcp/trust/allow \
  -H "Content-Type: application/json" \
  -d '{"input":{"agent":{"trust_level":"trusted","svid_verified":true},"operation":"write","tool":"filesystem"}}' | jq .
echo ""

echo "2. SEMI-TRUSTED agent - WRITE işlemi (DENIED olmalı):"
curl -s -X POST http://localhost:8181/v1/data/mcp/trust/allow \
  -H "Content-Type: application/json" \
  -d '{"input":{"agent":{"trust_level":"semi-trusted","svid_verified":true},"operation":"write","tool":"filesystem"}}' | jq .
echo ""

echo "3. SEMI-TRUSTED agent - READ işlemi (ALLOWED olmalı):"
curl -s -X POST http://localhost:8181/v1/data/mcp/trust/allow \
  -H "Content-Type: application/json" \
  -d '{"input":{"agent":{"trust_level":"semi-trusted","svid_verified":true},"operation":"read","tool":"filesystem"}}' | jq .
echo ""

echo "4. UNTRUSTED agent - READ işlemi (ALLOWED olmalı):"
curl -s -X POST http://localhost:8181/v1/data/mcp/trust/allow \
  -H "Content-Type: application/json" \
  -d '{"input":{"agent":{"trust_level":"untrusted","svid_verified":true},"operation":"read","tool":"filesystem"}}' | jq .
echo ""

echo "5. UNTRUSTED agent - WRITE işlemi (DENIED olmalı):"
curl -s -X POST http://localhost:8181/v1/data/mcp/trust/allow \
  -H "Content-Type: application/json" \
  -d '{"input":{"agent":{"trust_level":"untrusted","svid_verified":true},"operation":"write","tool":"filesystem"}}' | jq .
```

### Beklenen Çıktı

```
=== Senaryo 2: Trust Boundary Enforcement ===

1. TRUSTED agent - WRITE işlemi (ALLOWED olmalı):
{ "result": true }

2. SEMI-TRUSTED agent - WRITE işlemi (DENIED olmalı):
{ "result": false }

3. SEMI-TRUSTED agent - READ işlemi (ALLOWED olmalı):
{ "result": true }

4. UNTRUSTED agent - READ işlemi (ALLOWED olmalı):
{ "result": true }

5. UNTRUSTED agent - WRITE işlemi (DENIED olmalı):
{ "result": false }
```

### Trust Level Tablosu

| Trust Level | read | write | execute | admin |
|-------------|------|-------|---------|-------|
| trusted | ✅ | ✅ | ✅ | ✅ |
| semi-trusted | ✅ | ❌ | ❌ | ❌ |
| untrusted | ✅ | ❌ | ❌ | ❌ |

---

## Senaryo 3: Keycloak Token Exchange (SPIFFE → DPoP)

**Amaç:** Agent'ın SPIFFE SVID'ini Keycloak'a sunarak DPoP-bound access token aldığını göster

### Ön Bilgi

Token Exchange akışı:
1. Agent, SPIRE'dan JWT-SVID alır (otomatik, 5 dk rotasyon)
2. Agent, DPoP proof JWT oluşturur (ephemeral key pair)
3. Agent, Keycloak token endpoint'ine SVID + DPoP proof gönderir
4. Keycloak, SVID'i doğrular (SPIFFE federation) ve DPoP-bound token döner

### Komutlar

```bash
echo "=== Senaryo 3: Keycloak Token Exchange ==="
echo ""

# Keycloak port-forward (açık değilse)
kubectl port-forward -n keycloak svc/keycloak 8180:8080 &
sleep 2

echo "1. Keycloak Realm Bilgileri:"
curl -s http://localhost:8180/realms/mcp-identity | jq '{realm, public_key: .public_key[0:20], token_service: .["token-service"]}'
echo ""

echo "2. Keycloak OIDC Discovery:"
curl -s http://localhost:8180/realms/mcp-identity/.well-known/openid-configuration | jq '{issuer, token_endpoint, dpop_signing_alg_values_supported}'
echo ""

echo "3. Token Exchange - Trusted Agent (client_credentials + DPoP):"
# DPoP proof oluştur (gerçek uygulamada agent SDK bunu yapar)
DPOP_HEADER=$(echo -n '{"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"...","y":"..."}}' | base64 -w0)
DPOP_PAYLOAD=$(echo -n "{\"jti\":\"$(uuidgen)\",\"htm\":\"POST\",\"htu\":\"http://keycloak.keycloak.svc:8080/realms/mcp-identity/protocol/openid-connect/token\",\"iat\":$(date +%s)}" | base64 -w0)

# Keycloak token endpoint çağrısı — JWT client assertion (no static secret)
TOKEN_RESPONSE=$(curl -s -X POST http://localhost:8180/realms/mcp-identity/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=mcp-agent-trusted" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=<JWT_SVID>")

echo "$TOKEN_RESPONSE" | jq '{token_type, expires_in, scope}'
echo ""

echo "4. Access Token İçeriği (decoded):"
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
# JWT payload decode
echo "$ACCESS_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{iss, sub, azp, spiffe_id, trust_level, allowed_tools, exp}'
echo ""

echo "5. Token Doğrulama - Keycloak Introspection:"
curl -s -X POST http://localhost:8180/realms/mcp-identity/protocol/openid-connect/token/introspect \
  -d "client_id=mcp-agent-trusted" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=<JWT_SVID>" \
  -d "token=$ACCESS_TOKEN" | jq '{active, client_id, token_type, spiffe_id}'
echo ""

echo "6. Token Expiry Kontrolü (5 dakika TTL):"
EXP=$(echo "$ACCESS_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq -r '.exp')
IAT=$(echo "$ACCESS_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq -r '.iat')
echo "   Issued At:  $(date -d @$IAT '+%H:%M:%S')"
echo "   Expires At: $(date -d @$EXP '+%H:%M:%S')"
echo "   TTL:        $(($EXP - $IAT)) seconds"
```

### Beklenen Çıktı

```
=== Senaryo 3: Keycloak Token Exchange ===

1. Keycloak Realm Bilgileri:
{
  "realm": "mcp-identity",
  "public_key": "MIIBIjANBgkqhkiG9w...",
  "token_service": "http://localhost:8180/realms/mcp-identity/protocol/openid-connect"
}

2. Keycloak OIDC Discovery:
{
  "issuer": "http://localhost:8180/realms/mcp-identity",
  "token_endpoint": "http://localhost:8180/realms/mcp-identity/protocol/openid-connect/token",
  "dpop_signing_alg_values_supported": ["RS256", "ES256"]
}

3. Token Exchange - Trusted Agent:
{
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "mcp-tools"
}

4. Access Token İçeriği (decoded):
{
  "iss": "http://localhost:8180/realms/mcp-identity",
  "sub": "service-account-mcp-agent-service",
  "azp": "mcp-agent-service",
  "spiffe_id": "spiffe://mcp-identity.local/ns/mcp-agents/sa/mcp-agent-service",
  "trust_level": "trusted",
  "allowed_tools": ["filesystem", "database", "api"],
  "exp": 1704067500
}

5. Token Doğrulama - Keycloak Introspection:
{
  "active": true,
  "client_id": "mcp-agent-service",
  "token_type": "Bearer",
  "spiffe_id": "spiffe://mcp-identity.local/ns/mcp-agents/sa/mcp-agent-service"
}

6. Token Expiry Kontrolü (5 dakika TTL):
   Issued At:  14:00:00
   Expires At: 14:05:00
   TTL:        300 seconds
```

### Açıklama

| Adım | Bileşen | Açıklama |
|------|---------|----------|
| SVID → Keycloak | SPIFFE Federation | JWT-SVID, client assertion olarak kullanılır |
| DPoP Proof | Token Binding | Token, client'ın key pair'ine bağlanır |
| Access Token | Keycloak | SPIFFE ID + trust_level + allowed_tools claim'leri içerir |
| Introspection | Doğrulama | Token geçerliliği ve binding kontrolü |
| TTL: 300s | Auto-rotation | 5 dakikada token expire olur, yenisi alınır |

### Keycloak Realm Konfigürasyonu

Bu senaryo aşağıdaki Keycloak ayarlarını kullanır:
- **Clients:** `mcp-agent-trusted`, `mcp-agent-semi-trusted`, `mcp-agent-untrusted` (per-trust-level)
- **Auth Method:** `client-jwt` (JWT client assertion, no static secrets)
- **Protocol Mappers:** `spiffe_id`, `trust_level`, `allowed_tools` claim'leri
- **DPoP Policy:** `mcp-agent-dpop-policy` (tüm agent client'lara DPoP zorunlu)
- **SPIFFE Federation:** `spiffe-federation` identity provider (SPIRE JWKS doğrulama)

Realm export: `manifests/keycloak/mcp-realm.json`

---

## Senaryo 4: Tool Access Control

**Amaç:** Farklı trust level'ların farklı tool'lara erişebildiğini göster

### Komutlar

```bash
echo "=== Senaryo 4: Tool Access Control ==="
echo ""

echo "1. TRUSTED agent - SHELL erişimi (ALLOWED):"
curl -s -X POST http://localhost:8181/v1/data/mcp/trust/allow \
  -H "Content-Type: application/json" \
  -d '{"input":{"agent":{"trust_level":"trusted","svid_verified":true},"operation":"read","tool":"shell"}}' | jq .
echo ""

echo "2. SEMI-TRUSTED agent - SHELL erişimi (DENIED):"
curl -s -X POST http://localhost:8181/v1/data/mcp/trust/allow \
  -H "Content-Type: application/json" \
  -d '{"input":{"agent":{"trust_level":"semi-trusted","svid_verified":true},"operation":"read","tool":"shell"}}' | jq .
echo ""

echo "3. SEMI-TRUSTED agent - DATABASE erişimi (ALLOWED):"
curl -s -X POST http://localhost:8181/v1/data/mcp/trust/allow \
  -H "Content-Type: application/json" \
  -d '{"input":{"agent":{"trust_level":"semi-trusted","svid_verified":true},"operation":"read","tool":"database"}}' | jq .
echo ""

echo "4. UNTRUSTED agent - DATABASE erişimi (DENIED):"
curl -s -X POST http://localhost:8181/v1/data/mcp/trust/allow \
  -H "Content-Type: application/json" \
  -d '{"input":{"agent":{"trust_level":"untrusted","svid_verified":true},"operation":"read","tool":"database"}}' | jq .
```

### Tool Erişim Tablosu

| Trust Level | filesystem | database | api | shell | network |
|-------------|------------|----------|-----|-------|---------|
| trusted | ✅ | ✅ | ✅ | ✅ | ✅ |
| semi-trusted | ✅ | ✅ | ✅ | ❌ | ❌ |
| untrusted | ✅ | ❌ | ❌ | ❌ | ❌ |

---

## Senaryo 5: SVID Verification

**Amaç:** SVID doğrulanmamış agent'ların erişemediğini göster

### Komutlar

```bash
echo "=== Senaryo 5: SVID Verification ==="
echo ""

echo "1. TRUSTED agent - SVID verified=true (ALLOWED):"
curl -s -X POST http://localhost:8181/v1/data/mcp/trust/allow \
  -H "Content-Type: application/json" \
  -d '{"input":{"agent":{"trust_level":"trusted","svid_verified":true},"operation":"read","tool":"filesystem"}}' | jq .
echo ""

echo "2. TRUSTED agent - SVID verified=false (DENIED):"
curl -s -X POST http://localhost:8181/v1/data/mcp/trust/allow \
  -H "Content-Type: application/json" \
  -d '{"input":{"agent":{"trust_level":"trusted","svid_verified":false},"operation":"read","tool":"filesystem"}}' | jq .
echo ""

echo "3. Attack simulation - Spoofed trust level without SVID:"
curl -s -X POST http://localhost:8181/v1/data/mcp/trust/allow \
  -H "Content-Type: application/json" \
  -d '{"input":{"agent":{"trust_level":"trusted","svid_verified":false},"operation":"admin","tool":"shell"}}' | jq .
```

### Beklenen Çıktı

```
1. TRUSTED agent - SVID verified=true (ALLOWED):
{ "result": true }

2. TRUSTED agent - SVID verified=false (DENIED):
{ "result": false }

3. Attack simulation - Spoofed trust level without SVID:
{ "result": false }
```

### Açıklama

- SVID doğrulanmadan hiçbir işlem yapılamaz
- Trust level spoof edilse bile SVID olmadan erişim yok
- Defense in depth: Identity + Authorization

---

## Senaryo 6: SPIRE Identity Check

**Amaç:** SPIRE server'daki identity entry'lerini göster

### Komutlar

```bash
echo "=== Senaryo 6: SPIRE Identity Check ==="
echo ""

# SPIRE Server pod adını al
SPIRE_POD=$(kubectl get pods -n spire-system -l app=spire-server -o jsonpath='{.items[0].metadata.name}')

echo "1. Registered SPIFFE Entries:"
kubectl exec -n spire-system $SPIRE_POD -- /opt/spire/bin/spire-server entry show
echo ""

echo "2. SPIRE Server Health:"
kubectl exec -n spire-system $SPIRE_POD -- /opt/spire/bin/spire-server healthcheck
echo ""

echo "3. SPIRE Agents Status:"
kubectl exec -n spire-system $SPIRE_POD -- /opt/spire/bin/spire-server agent list
```

---

## Senaryo 7: Full Policy Response

**Amaç:** OPA'dan detaylı policy response al

### Komutlar

```bash
echo "=== Senaryo 7: Full Policy Response ==="
echo ""

echo "1. Trusted agent - Full response:"
curl -s -X POST http://localhost:8181/v1/data/mcp/trust/response \
  -H "Content-Type: application/json" \
  -d '{"input":{"agent":{"trust_level":"trusted","svid_verified":true},"operation":"write","tool":"database"}}' | jq .
echo ""

echo "2. Untrusted agent - Full response:"
curl -s -X POST http://localhost:8181/v1/data/mcp/trust/response \
  -H "Content-Type: application/json" \
  -d '{"input":{"agent":{"trust_level":"untrusted","svid_verified":true},"operation":"write","tool":"database"}}' | jq .
```

### Beklenen Çıktı

```json
// Trusted agent
{
  "result": {
    "allowed": true,
    "operation": "write",
    "tool": "database",
    "trust_level": "trusted"
  }
}

// Untrusted agent
{
  "result": {
    "allowed": false,
    "operation": "write",
    "tool": "database",
    "trust_level": "untrusted"
  }
}
```

---

## Senaryo 8: Live Demo Script

**Amaç:** Sunumda kullanılacak tek script

### Tam Demo Script

```bash
#!/bin/bash
# MCPIdentity Live Demo Script

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║          MCPIdentity Live Demo                                ║${NC}"
echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# 1. Zero Credentials Check
echo -e "${GREEN}[1/5] Zero Static Credentials Check${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -n "Checking for static credentials in trusted agent... "
CREDS=$(kubectl exec -n mcp-agents deployment/mcp-agent-trusted -- env 2>/dev/null | grep -E "(KEY|SECRET|PASSWORD)" || true)
if [ -z "$CREDS" ]; then
    echo -e "${GREEN}NONE FOUND ✓${NC}"
else
    echo -e "${RED}WARNING: $CREDS${NC}"
fi
echo ""

# 2. Trust Levels
echo -e "${GREEN}[2/5] Trust Level Configuration${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Trusted Agent:      $(kubectl exec -n mcp-agents deployment/mcp-agent-trusted -- printenv TRUST_LEVEL 2>/dev/null)"
echo "Semi-Trusted Agent: $(kubectl exec -n mcp-agents deployment/mcp-agent-semi-trusted -- printenv TRUST_LEVEL 2>/dev/null)"
echo "Untrusted Agent:    $(kubectl exec -n mcp-agents deployment/mcp-agent-untrusted -- printenv TRUST_LEVEL 2>/dev/null)"
echo ""

# 3. Policy Enforcement
echo -e "${GREEN}[3/5] Keycloak Token Exchange${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
TOKEN_RESPONSE=$(curl -s -X POST http://localhost:8180/realms/mcp-identity/protocol/openid-connect/token \
    -d "grant_type=client_credentials" \
    -d "client_id=mcp-agent-trusted" \
    -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
    -d "client_assertion=<JWT_SVID>")
echo -n "  Token Type: "
echo "$TOKEN_RESPONSE" | jq -r '.token_type'
echo -n "  Expires In: "
echo "$TOKEN_RESPONSE" | jq -r '.expires_in'
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
echo -n "  SPIFFE ID:  "
echo "$ACCESS_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq -r '.spiffe_id'
echo ""

echo -e "${GREEN}[4/5] Trust Boundary Policy Enforcement${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

test_policy() {
    local trust=$1
    local op=$2
    local tool=$3
    local expected=$4

    result=$(curl -s -X POST http://localhost:8181/v1/data/mcp/trust/allow \
        -H "Content-Type: application/json" \
        -d "{\"input\":{\"agent\":{\"trust_level\":\"$trust\",\"svid_verified\":true},\"operation\":\"$op\",\"tool\":\"$tool\"}}" | grep -o '"result":[^}]*' | cut -d: -f2)

    if [ "$result" == "$expected" ]; then
        echo -e "  $trust + $op + $tool = ${GREEN}$result ✓${NC}"
    else
        echo -e "  $trust + $op + $tool = ${RED}$result ✗ (expected $expected)${NC}"
    fi
}

test_policy "trusted" "write" "filesystem" "true"
test_policy "semi-trusted" "write" "filesystem" "false"
test_policy "semi-trusted" "read" "filesystem" "true"
test_policy "untrusted" "read" "filesystem" "true"
test_policy "untrusted" "write" "filesystem" "false"
echo ""

# 4. SVID Security
echo -e "${GREEN}[5/5] SVID Verification Security${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -n "  Trusted + SVID verified=true:  "
curl -s -X POST http://localhost:8181/v1/data/mcp/trust/allow \
    -H "Content-Type: application/json" \
    -d '{"input":{"agent":{"trust_level":"trusted","svid_verified":true},"operation":"admin","tool":"shell"}}' | grep -o '"result":[^}]*'

echo -n "  Trusted + SVID verified=false: "
curl -s -X POST http://localhost:8181/v1/data/mcp/trust/allow \
    -H "Content-Type: application/json" \
    -d '{"input":{"agent":{"trust_level":"trusted","svid_verified":false},"operation":"admin","tool":"shell"}}' | grep -o '"result":[^}]*'
echo ""

echo -e "${YELLOW}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║          Demo Complete!                                        ║${NC}"
echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════════╝${NC}"
```

### Kullanım

```bash
# Script'i kaydet
chmod +x demo.sh

# Çalıştır
./demo.sh
```

---

## Senaryo 9: SPIFFE SVID Fetch Demo

**Amaç:** Gerçek SPIFFE identity'lerin nasıl oluşturulduğunu ve dağıtıldığını göster

### Ön Bilgi

SPIFFE (Secure Production Identity Framework for Everyone) workload identity standardıdır:
- Her agent benzersiz bir SPIFFE ID alır
- SVID (SPIFFE Verifiable Identity Document) = X.509 veya JWT credential
- Otomatik rotation ve renewal
- No static secrets!

### Registered SPIFFE IDs

```
spiffe://mcp-identity.local/ns/mcp-agents/sa/mcp-agent-trusted
spiffe://mcp-identity.local/ns/mcp-agents/sa/mcp-agent-semi-trusted
spiffe://mcp-identity.local/ns/mcp-agents/sa/mcp-agent-untrusted
```

### Komutlar

```bash
echo "=== Senaryo 9: SPIFFE SVID Demo ==="
echo ""

# SPIRE Server pod
SPIRE_SERVER=$(kubectl get pods -n spire-system -l app=spire-server -o jsonpath='{.items[0].metadata.name}')

echo "1. SPIRE Server Health Check:"
kubectl exec -n spire-system $SPIRE_SERVER -- /opt/spire/bin/spire-server healthcheck
echo ""

echo "2. Registered SPIFFE Entries:"
kubectl exec -n spire-system $SPIRE_SERVER -- /opt/spire/bin/spire-server entry show
echo ""

echo "3. Connected SPIRE Agents:"
kubectl exec -n spire-system $SPIRE_SERVER -- /opt/spire/bin/spire-server agent list
echo ""

echo "4. Trust Bundle (Root of Trust):"
kubectl exec -n spire-system $SPIRE_SERVER -- /opt/spire/bin/spire-server bundle show -format spiffe | head -20
echo "... (truncated)"
echo ""

# SPIRE Agent pod
SPIRE_AGENT=$(kubectl get pods -n spire-system -l app=spire-agent -o jsonpath='{.items[0].metadata.name}')

echo "5. SVID Fetch from SPIRE Agent:"
kubectl exec -n spire-system $SPIRE_AGENT -- /opt/spire/bin/spire-agent api fetch x509 -socketPath /run/spire/sockets/agent.sock -write /tmp/
kubectl exec -n spire-system $SPIRE_AGENT -- ls -la /tmp/*.pem 2>/dev/null || echo "   X.509 SVIDs fetched to /tmp/"
echo ""

echo "6. JWT-SVID Fetch (for service-to-service auth):"
kubectl exec -n spire-system $SPIRE_AGENT -- /opt/spire/bin/spire-agent api fetch jwt -audience mcp-server -socketPath /run/spire/sockets/agent.sock 2>/dev/null | head -20 || echo "   JWT-SVID requires workload attestation from matching pod"
```

### Demo Script

```bash
# Kullanım
chmod +x scripts/demo-svid-fetch.sh
./scripts/demo-svid-fetch.sh
```

### Beklenen Çıktı

```
╔═══════════════════════════════════════════════════════════════╗
║     MCPIdentity - SPIFFE SVID Demonstration                   ║
╚═══════════════════════════════════════════════════════════════╝

[1/5] Checking SPIRE Server Status...
Server is healthy.
✓ SPIRE Server is healthy

[2/5] Listing Registered SPIFFE Entries...
Entry ID         : (uuid)
SPIFFE ID        : spiffe://mcp-identity.local/ns/mcp-agents/sa/mcp-agent-trusted
Parent ID        : spiffe://mcp-identity.local/spire/agent/k8s_psat/...
...

[5/5] Showing Trust Bundle...
{
  "keys": [
    {
      "kty": "RSA",
      "use": "x509-svid",
      ...
```

### Açıklama

| Bileşen | Açıklama |
|---------|----------|
| SPIFFE ID | Unique workload identity (URI format) |
| X.509 SVID | Certificate-based identity document |
| JWT-SVID | Token-based identity for APIs |
| Trust Bundle | Root CA certificates for validation |
| SPIRE Agent | Node-level daemon that issues SVIDs |
| SPIRE Server | Central authority for registration |

### Security Benefits

1. **Zero Static Credentials**: SVIDs are short-lived and auto-rotated
2. **Cryptographic Identity**: Can't be spoofed (signed by SPIRE)
3. **Workload Attestation**: Identity tied to actual workload, not config
4. **Federation Ready**: Can federate trust across clusters

---

## Temizlik

```bash
# Cluster'ı sil
k3d cluster delete mcp-identity

# Port forward'ları durdur
pkill -f "port-forward"
```

---

## Sorun Giderme

### OPA'ya bağlanamıyorum
```bash
# Port forward kontrol
kubectl port-forward -n opa-system svc/opa 8181:8181

# OPA health check
curl http://localhost:8181/health
```

### Agent'lar çalışmıyor
```bash
# Pod durumu
kubectl get pods -n mcp-agents

# Loglar
kubectl logs -n mcp-agents deployment/mcp-agent-trusted
```

### SPIRE sorunları
```bash
# SPIRE server logları
kubectl logs -n spire-system spire-server-0

# SPIRE agent logları
kubectl logs -n spire-system -l app=spire-agent
```
