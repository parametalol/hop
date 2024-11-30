#!/bin/bash

set -euo pipefail

CERT_DIR=${1:-certificates}
SVC_NAME=${2:-hop}
SUBJ=${3:-"/C=NO/ST=State/L=City/O=Organization/CN=$SVC_NAME"}

mkdir -p "$CERT_DIR/private"

echo "Creating a Certificate Signing Request for the backend service $SVC_NAME..."
openssl req -new -subj "$SUBJ" \
  -key "$CERT_DIR/private/$SVC_NAME.key" \
  -out "$CERT_DIR/$SVC_NAME.csr"

echo "Using the CA $CERT_DIR/ca.crt to sign the CSR and generate the certificate for the backend service $SVC_NAME..."
openssl x509 -req -CAcreateserial -days 365 -sha256 \
  -in "$CERT_DIR/$SVC_NAME.csr" \
  -CA "$CERT_DIR/ca.crt" \
  -CAkey "$CERT_DIR/private/ca.key" \
  -out "$CERT_DIR/$SVC_NAME.crt"
