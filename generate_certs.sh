#!/bin/bash

set -euo pipefail

CERT_DIR=${1:-certificates}
SVC_NAME=${2:-hop}
SUBJ=${3:-"/C=NO/ST=State/L=City/O=Organization/CN=$SVC_NAME"}

mkdir -p "$CERT_DIR/private"

if [[ -e "$CERT_DIR/ca.crt" ]]
then
  echo "Reusing the existing $CERT_DIR/ca.crt certificate"
else
  echo "Creating a CA private key and self-signed CA certificate..."
  openssl req -x509 -new -nodes -sha256 -days 3650 -subj "$SUBJ CA" \
    -out "$CERT_DIR/ca.crt" \
    -keyout "$CERT_DIR/private/ca.key"
fi

echo "Creating a private key for the service $SVC_NAME..."
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$CERT_DIR/private/$SVC_NAME.key"
