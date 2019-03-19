#!/bin/sh

if [ ! -f certificates/private/key.pem -o ! -f certificates/certificate.pem ]
then
  echo "Create the certificate and the key with gen_certs.sh script first"
  exit 1
fi

kubectl create secret tls hop-tls --cert certificates/certificate.pem --key certificates/private/key.pem
