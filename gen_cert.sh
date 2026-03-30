#!/usr/bin/env bash

###############################################################################
# Module: Certificate Generation for Project 3 TLS/SSL
#
# Why this script was expanded from the originally provided version:
#
# The original script only generated a single self-signed server certificate.
# That was not enough for the finished project requirements because:
#
# 1. Part 1 requires the client to verify the server certificate.
#    For a cleaner and more realistic trust model, this script now generates
#    a Certificate Authority (CA) certificate and signs the server certificate
#    with that CA.
#
# 2. Part 3 requires mutual TLS (mTLS).
#    That means the server must verify a client certificate, so this script
#    also generates a client key/certificate pair signed by the same CA.
#
# 3. Local hostname verification should work correctly.
#    The server certificate now includes Subject Alternative Name (SAN)
#    entries for both `localhost` and `127.0.0.1`, so Python's TLS hostname
#    verification succeeds during local testing.
#
# 4. Modern OpenSSL/Python validation expects a real CA certificate layout.
#    The CA certificate is generated with proper CA extensions so certificate
#    validation works correctly with current TLS libraries.
#
# What this script now generates:
#
# - certs/ca.crt and certs/ca.key
# - certs/server.crt and certs/server.key
# - certs/client.crt and certs/client.key
#
# This keeps certificate setup repeatable and makes the project easy to run
# and grade locally with a single command: `./gen_cert.sh`
###############################################################################

set -euo pipefail

CERT_DIR="${1:-certs}"
DAYS="${DAYS:-365}"

mkdir -p "${CERT_DIR}"

CA_KEY="${CERT_DIR}/ca.key"
CA_CERT="${CERT_DIR}/ca.crt"
SERVER_KEY="${CERT_DIR}/server.key"
SERVER_CSR="${CERT_DIR}/server.csr"
SERVER_CERT="${CERT_DIR}/server.crt"
CLIENT_KEY="${CERT_DIR}/client.key"
CLIENT_CSR="${CERT_DIR}/client.csr"
CLIENT_CERT="${CERT_DIR}/client.crt"
SERVER_EXT="${CERT_DIR}/server_ext.cnf"
CLIENT_EXT="${CERT_DIR}/client_ext.cnf"

cat > "${SERVER_EXT}" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

cat > "${CLIENT_EXT}" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectAltName=DNS:localhost
EOF

openssl req -x509 -newkey rsa:4096 -sha256 -nodes \
  -keyout "${CA_KEY}" \
  -out "${CA_CERT}" \
  -days "${DAYS}" \
  -subj "/CN=Project3 TLS CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

openssl req -new -newkey rsa:3072 -sha256 -nodes \
  -keyout "${SERVER_KEY}" \
  -out "${SERVER_CSR}" \
  -subj "/CN=localhost"

openssl x509 -req -sha256 \
  -in "${SERVER_CSR}" \
  -CA "${CA_CERT}" \
  -CAkey "${CA_KEY}" \
  -CAcreateserial \
  -out "${SERVER_CERT}" \
  -days "${DAYS}" \
  -extfile "${SERVER_EXT}"

openssl req -new -newkey rsa:3072 -sha256 -nodes \
  -keyout "${CLIENT_KEY}" \
  -out "${CLIENT_CSR}" \
  -subj "/CN=Project3 TLS Client"

openssl x509 -req -sha256 \
  -in "${CLIENT_CSR}" \
  -CA "${CA_CERT}" \
  -CAkey "${CA_KEY}" \
  -CAcreateserial \
  -out "${CLIENT_CERT}" \
  -days "${DAYS}" \
  -extfile "${CLIENT_EXT}"

rm -f "${SERVER_CSR}" "${CLIENT_CSR}" "${SERVER_EXT}" "${CLIENT_EXT}"

printf 'Generated certificate materials in %s\n' "${CERT_DIR}"
printf '  CA cert:      %s\n' "${CA_CERT}"
printf '  Server cert:  %s\n' "${SERVER_CERT}"
printf '  Client cert:  %s\n' "${CLIENT_CERT}"
