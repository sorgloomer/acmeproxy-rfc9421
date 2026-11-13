# Caddy plugin

Caddy DNS provider module `dns.providers.acmeproxy_rfc9421` for
acmeproxy-rfc9421.

## Build Caddy with xcaddy

```bash
xcaddy build --with github.com/sorgloomer/acmeproxy-rfc9421/clients/caddy
```

To build from a local checkout of this repository:

```bash
xcaddy build --with github.com/sorgloomer/acmeproxy-rfc9421/clients/caddy \
  --replace github.com/sorgloomer/acmeproxy-rfc9421=.
```

## Key

```bash
./keygen.sh ed25519 caddy   # or ecdsa / rsa
```

`caddy-<hostname>.pem` is the PKCS#8 private key, used as `KEY_PATH` or `key_path`.
`caddy-<hostname>.pub` goes into the server config as `keys = { caddy = "<contents>" }` of a `[[client]]` entry.

## Configure

Settings left empty fall back to `ACMEPROXY_ENDPOINT`, `KEY_ID`, `KEY_PATH`
and `KEY_VALUE`.

```caddyfile
{
	acme_dns acmeproxy_rfc9421 https://acmeproxy.example.com {
		key_id   caddy
		key_path /etc/caddy/caddy-<hostname>.pem
	}
}
```

Subdirectives are `endpoint`, `key_id`, `key_path` and `key_value`. Caddy
placeholders such as `{env.NAME}` work in each of them.
