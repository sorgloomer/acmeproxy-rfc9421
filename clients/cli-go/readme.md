# cli-go

An acmeproxy-rfc9421 client that speaks the protocol of lego's
[`exec`](https://go-acme.github.io/lego/dns/exec/) DNS provider:

```
cli-go present|cleanup <fqdn> <value>
```

[Traefik](../traefik) runs it through `EXEC_PATH`, and the
[acmesh-go](../acmesh-go) acme.sh script calls it the same way.

## Install

```bash
CGO_ENABLED=0 go install github.com/sorgloomer/acmeproxy-rfc9421/clients/cli-go@latest
```

## Key

```bash
./keygen.sh ed25519 servera   # or ecdsa / rsa
```

`servera-<hostname>.pem` is the PKCS#8 private key. `servera-<hostname>.pub` goes into the server
config as `keys = { servera = "<contents>" }` of a `[[client]]` entry.

## Configure

```
ACMEPROXY_ENDPOINT=https://acmeproxy.example.com
KEY_ID=servera
KEY_PATH=/path/to/servera-<hostname>.pem    # or KEY_VALUE=<PEM text>
```
