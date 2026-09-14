#!/usr/bin/env bash
# gen_certs.sh
# ─────────────────────────────────────────────────────────────────────────────
# Generates a complete PKI for the SEP2 test server:
#
#   certs/
#   ├── ca.crt / ca.key          — Test CA
#   ├── server.crt / server.key  — Server TLS certificate (CN=localhost)
#   ├── client_registered.crt    — "Probe D" client: valid chain, will be
#   │   client_registered.key      registered in config.yaml
#   ├── client_unregistered.crt  — "Probe C" client: valid chain, NOT in ACL
#   │   client_unregistered.key
#   └── client_selfsigned.crt    — "Probe B" client: self-signed (no CA)
#       client_selfsigned.key
#
# After running this script:
#   python server.py --show-lfdi certs/client_registered.crt
# …and paste the printed LFDI into config.yaml → acl.registered_lfdis
#
# Requirements: openssl (any recent version)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail
CERT_DIR="certs"
mkdir -p "$CERT_DIR"

DAYS_CA=3650
DAYS_LEAF=825      # < 2 years per Apple/Chrome policy
KEY_BITS=2048

echo "────────────────────────────────────────────"
echo "  Generating SEP2 test PKI"
echo "────────────────────────────────────────────"

# ── 1. Test CA ────────────────────────────────────────────────────────────────
echo "[1/5] Test CA…"
openssl genrsa -out "$CERT_DIR/ca.key" $KEY_BITS 2>/dev/null

openssl req -new -x509 \
  -key  "$CERT_DIR/ca.key" \
  -out  "$CERT_DIR/ca.crt" \
  -days $DAYS_CA \
  -subj "/C=US/O=SEP2 Test/CN=SEP2 Test CA" \
  -extensions v3_ca \
  -addext "basicConstraints=critical,CA:TRUE" \
  2>/dev/null

# ── 2. Server cert ────────────────────────────────────────────────────────────
echo "[2/5] Server certificate (CN=localhost + SAN)…"
openssl genrsa -out "$CERT_DIR/server.key" $KEY_BITS 2>/dev/null

openssl req -new \
  -key  "$CERT_DIR/server.key" \
  -out  "$CERT_DIR/server.csr" \
  -subj "/C=US/O=SEP2 Test/CN=localhost" \
  2>/dev/null

cat > /tmp/sep2_server_ext.cnf <<EOF
[v3_req]
subjectAltName = @alt_names
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = localhost
DNS.2 = *.local
IP.1  = 127.0.0.1
IP.2  = ::1
EOF

openssl x509 -req \
  -in      "$CERT_DIR/server.csr" \
  -CA      "$CERT_DIR/ca.crt" \
  -CAkey   "$CERT_DIR/ca.key" \
  -CAcreateserial \
  -out     "$CERT_DIR/server.crt" \
  -days    $DAYS_LEAF \
  -extfile /tmp/sep2_server_ext.cnf \
  -extensions v3_req \
  2>/dev/null

# ── 3. Registered client cert ─────────────────────────────────────────────────
echo "[3/5] Client cert – registered (Probe D)…"
openssl genrsa -out "$CERT_DIR/client_registered.key" $KEY_BITS 2>/dev/null

openssl req -new \
  -key  "$CERT_DIR/client_registered.key" \
  -out  "$CERT_DIR/client_registered.csr" \
  -subj "/C=US/O=SEP2 Test/CN=SEP2 Registered Client" \
  2>/dev/null

cat > /tmp/sep2_client_ext.cnf <<EOF
[v3_req]
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF

openssl x509 -req \
  -in      "$CERT_DIR/client_registered.csr" \
  -CA      "$CERT_DIR/ca.crt" \
  -CAkey   "$CERT_DIR/ca.key" \
  -CAcreateserial \
  -out     "$CERT_DIR/client_registered.crt" \
  -days    $DAYS_LEAF \
  -extfile /tmp/sep2_client_ext.cnf \
  -extensions v3_req \
  2>/dev/null

# ── 4. Unregistered client cert ───────────────────────────────────────────────
echo "[4/5] Client cert – unregistered (Probe C)…"
openssl genrsa -out "$CERT_DIR/client_unregistered.key" $KEY_BITS 2>/dev/null

openssl req -new \
  -key  "$CERT_DIR/client_unregistered.key" \
  -out  "$CERT_DIR/client_unregistered.csr" \
  -subj "/C=US/O=SEP2 Test/CN=SEP2 Unregistered Client" \
  2>/dev/null

openssl x509 -req \
  -in      "$CERT_DIR/client_unregistered.csr" \
  -CA      "$CERT_DIR/ca.crt" \
  -CAkey   "$CERT_DIR/ca.key" \
  -CAcreateserial \
  -out     "$CERT_DIR/client_unregistered.crt" \
  -days    $DAYS_LEAF \
  -extfile /tmp/sep2_client_ext.cnf \
  -extensions v3_req \
  2>/dev/null

# ── 5. Self-signed client cert ────────────────────────────────────────────────
echo "[5/5] Client cert – self-signed (Probe B)…"
openssl genrsa -out "$CERT_DIR/client_selfsigned.key" $KEY_BITS 2>/dev/null

openssl req -new -x509 \
  -key  "$CERT_DIR/client_selfsigned.key" \
  -out  "$CERT_DIR/client_selfsigned.crt" \
  -days $DAYS_LEAF \
  -subj "/C=US/O=SEP2 Test/CN=SEP2 Self-Signed Client" \
  2>/dev/null

# ── Cleanup temporaries ───────────────────────────────────────────────────────
rm -f "$CERT_DIR"/*.csr "$CERT_DIR"/*.srl /tmp/sep2_*.cnf

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════"
echo "  Certificates written to ./$CERT_DIR/"
echo ""
echo "  File                           Purpose"
echo "  ─────────────────────────────────────────"
echo "  ca.crt / ca.key                Test CA (server uses for client verification)"
echo "  server.crt / server.key        Server TLS"
echo "  client_registered.{crt,key}    Probe D  (valid cert, register LFDI in config)"
echo "  client_unregistered.{crt,key}  Probe C  (valid cert, NOT in ACL)"
echo "  client_selfsigned.{crt,key}    Probe B  (self-signed, rejected by default)"
echo "  [no cert]                      Probe A  (use without --cert flag)"
echo ""
echo "  Next step – compute the LFDI for the registered client and add it to"
echo "  config.yaml → acl.registered_lfdis:"
echo ""
echo "      python server.py --show-lfdi certs/client_registered.crt"
echo ""
echo "════════════════════════════════════════════"
