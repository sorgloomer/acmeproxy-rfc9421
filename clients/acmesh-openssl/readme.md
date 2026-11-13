# acme.sh client (OpenSSL)

An acme.sh DNS API script, written in POSIX shell, that signs requests with
OpenSSL 3.

## Install

```bash
curl -fsSL -o ~/.acme.sh/dnsapi/dns_acmeproxy_rfc9421.sh \
  https://raw.githubusercontent.com/sorgloomer/acmeproxy-rfc9421/main/clients/acmesh-openssl/dns_acmeproxy_rfc9421.sh
```

## Key

```bash
./keygen.sh ed25519 servera   # or ecdsa / rsa
```

`servera-<hostname>.pem` is the PKCS#8 private key. `servera-<hostname>.pub` goes into the server
config as `keys = { servera = "<contents>" }` of a `[[client]]` entry.

## Use

```bash
export ACMEPROXY_ENDPOINT=https://acmeproxy.example.com
export KEY_ID=servera
export KEY_PATH=$HOME/.acme.sh/servera-$(uname -n).pem   # or KEY_VALUE="$(cat ...)"
acme.sh --issue --dns dns_acmeproxy_rfc9421 -d servicea.example.com
```

The settings are saved to acme.sh's `account.conf`, so renewals run without
them.
