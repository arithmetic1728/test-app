#!/bin/sh

set -e

CERTS_DIR="$(dirname -- "$(realpath -- "$0")")"

if [[ -f *.pem ]]; then
    rm *.pem
fi

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ${CERTS_DIR}/ca_private_key.pem
openssl req -x509 -key ${CERTS_DIR}/ca_private_key.pem -subj /CN=proxy -out ${CERTS_DIR}/ca_cert.pem
