#!/bin/bash

set -euo pipefail

CERT_DIR=${1:-certificates}
SVC_NAME=${2:-hop}
SUBJ=${3:-"/C=NO/ST=State/L=City/O=Organization/CN=$SVC_NAME"}
NAMESPACE=${NAMESPACE:-default}

mkdir -p "$CERT_DIR/private"

echo "Creating a Certificate Signing Request for the backend service $SVC_NAME.$NAMESPACE..."
openssl req -new -subj "$SUBJ" \
  -addext "subjectAltName = DNS:$SVC_NAME, DNS:$SVC_NAME.$NAMESPACE, DNS:$SVC_NAME.$NAMESPACE.svc.cluster.local" \
  -key "$CERT_DIR/private/$SVC_NAME.key" \
  -out "$CERT_DIR/$SVC_NAME.csr"

cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: $SVC_NAME
spec:
  request: $(base64 --wrap=0 "$CERT_DIR/$SVC_NAME.csr")
  signerName: kubernetes.io/kubelet-serving
  usages:
  - digital signature
  - key encipherment
  - server auth
EOF

kubectl certificate approve "$SVC_NAME"

echo "Storing $SVC_NAME certificate in $CERT_DIR/$SVC_NAME.crt..."
kubectl get csr "$SVC_NAME" -o jsonpath='{.status.certificate}' | base64 -d > "$CERT_DIR/$SVC_NAME.crt"

echo "Creating $SVC_NAME secret with the certificate and the key..."
kubectl create secret tls \
  "$SVC_NAME-tls" \
  --cert="$CERT_DIR/$SVC_NAME.crt" \
  --key="$CERT_DIR/private/$SVC_NAME.key"
