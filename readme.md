# acmeproxy-rfc9421

An [acmeproxy](https://github.com/mdbraber/acmeproxy) style ACME DNS-01
challenge proxy, authenticated with
[RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421).

One server holds the DNS provider credentials. Each client holds only its own
private key. The server knows each client's public key and the domains it may
validate, and creates nothing but `_acme-challenge` TXT records for them.
See the [specification](docs/specification.fixed.md) and the
[API](docs/api.md).

| Directory | |
|-----------|-|
| [`servers/golang`](servers/golang) | The server: TOML config, any libdns provider, xcaddy-style custom builds. |
| [`clients/caddy`](clients/caddy) | Caddy DNS provider module, built with xcaddy. |
| [`clients/cli-go`](clients/cli-go) | Go client for lego's `exec` DNS provider protocol. |
| [`clients/traefik`](clients/traefik) | Traefik setup, using cli-go. |
| [`clients/acmesh-openssl`](clients/acmesh-openssl) | acme.sh DNS API in shell, signing with OpenSSL. |
| [`clients/acmesh-go`](clients/acmesh-go) | acme.sh DNS API that passes the challenge to cli-go. |
| [`lib/golang`](lib/golang) | Code shared by the Go programs. |

## Quick start

```bash
go install github.com/sorgloomer/acmeproxy-rfc9421/servers/golang/cmd/acmeproxy@latest
clients/caddy/keygen.sh ed25519 servera   # writes servera-<hostname>.pem and .pub
```

`acmeproxy.toml`:

```toml
[clients.servera]
pubkey = "MCowBQYDK2VwAyEA..."            # contents of servera-<hostname>.pub
domains = { "servicea.example.com" = "default" }

[providers.default]
provider = "hetzner"
api_token = "..."
```

```bash
acmeproxy -config acmeproxy.toml
```

Then configure a client with `ACMEPROXY_ENDPOINT`, `KEY_ID=servera` and
`KEY_PATH=servera-<hostname>.pem`, as described in its readme.

## Development

The repository is a single Go module (Go 1.27+).

```bash
go test ./...
```

`tests/e2e` runs every client against the real server, with keys made by each
client's `keygen.sh`. It needs `sh`, `openssl`, `od` and `curl`.
