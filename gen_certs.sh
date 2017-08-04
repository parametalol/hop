#!/bin/sh
rm -rf certificates
mkdir -p certificates/private certificates/newcerts
echo -n 01 > certificates/serial
touch certificates/index.txt

SERVICE_NAME=$1

openssl req -x509 -nodes -newkey rsa:2048 -config openssl.cnf \
  -subj '/C=US/CN=$SERVICE_NAME CA' -keyout certificates/private/cakey.pem \
  -out certificates/cacertificate.pem

echo ... generate a certificate signing request with the common name "$SERVICE_NAME"
openssl req -new -nodes -config openssl.cnf -subj "/C=US/CN=$SERVICE_NAME" \
  -keyout certificates/private/key.pem \
  -out certificates/req.pem

echo ... have the CA sign the certificate
openssl ca -batch -config openssl.cnf -keyfile certificates/private/cakey.pem \
  -cert certificates/cacertificate.pem \
  -out certificates/certificate.pem \
  -infiles certificates/req.pem
