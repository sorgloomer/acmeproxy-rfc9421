# acme.sh client (Go)

An acme.sh DNS API script that only passes the challenge to the
[cli-go](../cli-go) Go client, which does the signing.

## Install

```bash
go install github.com/sorgloomer/acmeproxy-rfc9421/clients/cli-go@latest
curl -fsSL -o ~/.acme.sh/dnsapi/dns_acmeproxy_rfc9421.sh \
  https://raw.githubusercontent.com/sorgloomer/acmeproxy-rfc9421/main/clients/acmesh-go/dns_acmeproxy_rfc9421.sh
```

## Key

```bash
./keygen.sh ed25519 servera   # or ecdsa / rsa
```

`servera-<hostname>.pem` is the PKCS#8 private key. `servera-<hostname>.pub` goes into the server
config as `pubkey` of `[clients.servera]`.

## Use

```bash
export ACMEPROXY_ENDPOINT=https://acmeproxy.example.com
export KEY_ID=servera
export KEY_PATH=$HOME/.acme.sh/servera-$(uname -n).pem
export ACMEPROXY_BIN=$HOME/go/bin/cli-go   # if not on acme.sh's PATH
acme.sh --issue --dns dns_acmeproxy_rfc9421 -d servicea.example.com
```
