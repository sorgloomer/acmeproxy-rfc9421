# acmeproxy-rfc9421 server

## Docker example

A server with the [Hetzner](https://github.com/libdns/hetzner) (Cloud DNS API)
provider, for the clients `foo` and `bar`, each allowed one domain.

`Dockerfile`:

```dockerfile
FROM golang:1.27-alpine AS build
RUN go install github.com/sorgloomer/acmeproxy-rfc9421/servers/golang/cmd/xacmeproxy@latest
RUN CGO_ENABLED=0 xacmeproxy build \
    --with github.com/libdns/hetzner/v2 \
	--output /acmeproxy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /acmeproxy /acmeproxy
ENTRYPOINT ["/acmeproxy"]
```

`compose.yaml`:

```yaml
services:
  acmeproxy:
    build: .
    ports:
      - "9095:9095"
    environment:
      ACMEPROXY_CONFIG: |
        [clients.foo]
        pubkey = "MCowBQYDK2VwAyEA1ZrIrT14+NvwBBFsBT06tFvA43/DHEVrnvsa0CzCR4c="
        domains = { "foo.example.com" = "hetzner" }

        [clients.bar]
        pubkey = "MCowBQYDK2VwAyEAqu/kRCOWvA0CsS/rkiQyCIwpPoxa0w/oHjcZ1OGp8So="
        domains = { "bar.example.com" = "hetzner" }

        [providers.hetzner]
        provider = "hetzner"
        api_token = "${HETZNER_API_TOKEN}"
```

`.env`, next to `compose.yaml`, which Compose reads to fill in
`${HETZNER_API_TOKEN}`:

```
HETZNER_API_TOKEN=your-hetzner-cloud-api-token
```

```bash
docker compose up -d
```

Each client creates its key pair with its own `keygen.sh`. The `.pub` file
goes into the client's `pubkey`.

## Build

The default build includes the `hetzner` (`libdns/hetzner/v2`) and
`cloudflare` providers:

```bash
go install github.com/sorgloomer/acmeproxy-rfc9421/servers/golang/cmd/acmeproxy@latest
```

For other providers, build your own binary with `xacmeproxy`, the way xcaddy
builds Caddy:

```bash
go install github.com/sorgloomer/acmeproxy-rfc9421/servers/golang/cmd/xacmeproxy@latest
xacmeproxy build --with github.com/libdns/route53 --with github.com/libdns/hetzner/v2 --output acmeproxy
```

* `--with <module>[@<version>][=<local dir>]` adds a libdns provider. Its name
  in the configuration is the last element of the module path, skipping a
  version suffix (`route53`, `hetzner`). The provider must implement the
  libdns v1 interfaces.
* `--with github.com/sorgloomer/acmeproxy-rfc9421[@<version>][=<dir>]` picks
  the server version, or a local checkout.
* `GOOS` and `GOARCH` work as usual for cross builds.

## Run

```bash
acmeproxy -config acmeproxy.toml -check   # validate
acmeproxy -config acmeproxy.toml          # serve
acmeproxy -list-providers
```

## Configuration

The TOML configuration is read from, in order of precedence:
1. `ACMEPROXY_CONFIG`, which holds the TOML itself;
2. the `-config` file;
3. the `ACMEPROXY_CONFIG_FILE` file;
4. `acmeproxy.toml`.

Setting both `ACMEPROXY_CONFIG` and `ACMEPROXY_CONFIG_FILE` is an error. See
[acmeproxy.example.toml](acmeproxy.example.toml).

`[server]`: these environment variables take precedence over the file:

| Key | Environment | Default |
|-----|-------------|---------|
| `bind` | `ACMEPROXY_BIND` | all interfaces |
| `port` | `ACMEPROXY_PORT` | `9095` |
| `signature_expiration` | `ACMEPROXY_SIGNATURE_EXPIRATION` | `5m`, the maximum age of a signature |
| `clock_drift` | `ACMEPROXY_CLOCK_DRIFT` | `30s`, how far a signature may be in the future |
| `tls_cert`, `tls_key` | | unset, which means plain HTTP |
| `record_ttl` | | `60s` |

`[clients.<keyid>]`:
* `pubkey`: the client's public key as base64 SPKI, as written by `keygen.sh`.
* `domains`: maps a domain, or `*.domain` for everything below it, to a
  provider.

`[providers.<name>]`:
* `provider`: the provider type.
* The provider's settings, under its JSON field names.

Run the server behind HTTPS, and keep `Host` and the path unchanged in any
reverse proxy.
