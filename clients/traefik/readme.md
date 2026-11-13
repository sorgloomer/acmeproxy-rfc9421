# Traefik client

Traefik cannot load DNS provider plugins. It can run a program for each
challenge through lego's [`exec`](https://go-acme.github.io/lego/dns/exec/)
provider. [cli-go](../cli-go) is that program:
`cli-go present|cleanup <fqdn> <value>`. It works with any lego based
tool.

## Install into the Traefik image

```dockerfile
FROM golang:1.27-alpine AS build
RUN CGO_ENABLED=0 go install github.com/sorgloomer/acmeproxy-rfc9421/clients/cli-go@latest

FROM traefik:v3
COPY --from=build /go/bin/cli-go /usr/local/bin/
```

## Key

```bash
./keygen.sh ed25519 traefik   # or ecdsa / rsa
```

`traefik-<hostname>.pem` is the PKCS#8 private key (`KEY_PATH`). `traefik-<hostname>.pub` goes into
the server config as `keys = { traefik = "<contents>" }` of a `[[client]]` entry.

## Configure

```yaml
certificatesResolvers:
  acmeproxy:
    acme:
      email: admin@example.com
      storage: /letsencrypt/acme.json
      dnsChallenge:
        provider: exec
```

Environment of the Traefik container:

```
EXEC_PATH=/usr/local/bin/cli-go
ACMEPROXY_ENDPOINT=https://acmeproxy.example.com
KEY_ID=traefik
KEY_PATH=/run/secrets/traefik-<hostname>.pem
```
