#!/bin/sh
# Usage: ./keygen.sh [ed25519|ecdsa|rsa] [name]
# Creates <name>-<hostname>.pem, the PKCS#8 private key for KEY_PATH, and
# <name>-<hostname>.pub, the base64 SPKI public key for the server's pubkey
# setting. Needs OpenSSL 3.
set -eu
type="${1:-ed25519}"
name="${2:-acmeproxy}-$(uname -n)"
umask 077
case "$type" in
ed25519) openssl genpkey -quiet -algorithm ed25519 -out "$name.pem" ;;
ecdsa) openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$name.pem" ;;
rsa) openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$name.pem" ;;
*)
  echo "usage: $0 [ed25519|ecdsa|rsa] [name]" >&2
  exit 2
  ;;
esac
openssl pkey -in "$name.pem" -pubout -outform DER | openssl base64 -A >"$name.pub"
echo >>"$name.pub"
echo "wrote $name.pem (KEY_PATH) and $name.pub (server pubkey)"
