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
      HETZNER_TOKEN: ${HETZNER_TOKEN}
      ACMEPROXY_CONFIG: |
        [[client]]
        keys = { foo = "MCowBQYDK2VwAyEA1ZrIrT14+NvwBBFsBT06tFvA43/DHEVrnvsa0CzCR4c=" }
        domains = { "foo.example.com" = "hetzner" }

        [[client]]
        keys = { bar = "MCowBQYDK2VwAyEAqu/kRCOWvA0CsS/rkiQyCIwpPoxa0w/oHjcZ1OGp8So=" }
        domains = { "bar.example.com" = "hetzner" }

        [providers.hetzner]
        api_token = "$${{ env.HETZNER_TOKEN }}"
```

`.env`, next to `compose.yaml`, which Compose reads to fill in
`${HETZNER_TOKEN}`, the container's `HETZNER_TOKEN` variable:

```
HETZNER_TOKEN=your-hetzner-cloud-api-token
```

The server replaces `${{ env.HETZNER_TOKEN }}` with that variable (see
[Interpolation](#interpolation)). Compose has its own `${...}` syntax, so the
leading `$` is doubled to `$$` to pass the server's `${{` through unchanged.
In a file that Compose does not process, write `api_token = "${{ env.HETZNER_TOKEN }}"`.

```bash
docker compose up -d
```

Each client creates its key pair with its own `keygen.sh`. The `.pub` file's
contents go into `keys`, under the client's `KEY_ID`.

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

`[[client]]`, one entry per group of keys that share domains. Every key of an
entry may manage every domain of that entry.
* `keys`: maps a keyid to a base64 SPKI public key, as written by
  `keygen.sh`. The keyid is the client's `KEY_ID`, and may appear only once
  in the whole configuration.
* `domains`: maps a domain, or `*.domain` for everything below it, to a
  provider.

`[providers.<name>]`:
* `provider`: the provider type. It defaults to `<name>`.
* The provider's settings, under its JSON field names.

### Interpolation

Every string value in the configuration, at any depth, may contain:

* `${{ env.NAME }}`, which is replaced by the environment variable `NAME`. A
  variable that is not set is an error, while an empty one gives an empty
  string.
* `${{$}}`, which is replaced by a literal `${{`.

```toml
[providers.hetzner]
api_token = "${{ env.HETZNER_TOKEN }}"
```

Keys are not interpolated, and text that was substituted is not interpolated
again.

Run the server behind HTTPS, and keep `Host` and the path unchanged in any
reverse proxy.
