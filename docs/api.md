# acmeproxy-rfc9421 API

```
POST {endpoint}/present {"fqdn": "_acme-challenge.<domain>", "value": "<txt value>"}
POST {endpoint}/cleanup {"fqdn": "_acme-challenge.<domain>", "value": "<txt value>"}
```

`present` adds the TXT record, `cleanup` removes it. Other TXT values on the
same name are kept. `fqdn` may have a trailing dot. `value` is 1–255
characters of `A-Z a-z 0-9 - _ + / =`.

## Headers

| Header            | Value |
|-------------------|-------|
| `Content-Type`    | `application/json` |
| `Content-Digest`  | [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530) digest of the body: `sha-256=:<base64>:` (or `sha-512`) |
| `Signature-Input` | [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) signature metadata, see below |
| `Signature`       | RFC 9421 signature: `sig1=:<base64>:` |

```
Signature-Input: sig1=("@method" "@authority" "@path" "content-type" "content-digest");created=1794504579;keyid="servera";alg="ed25519";nonce="NNCC7YME5WEMLSNRTRXO4GFM3M"
```

* Covered components: at least `@method`, `@authority`, `@path`,
  `content-type` and `content-digest`.
* `created` (required): accepted when no older than `signature_expiration`
  (default 5 minutes) and no further in the future than `clock_drift` (default 30 seconds).
* `keyid` (required): the name of the client's key in the `keys` of a `[[client]]` entry on the server.
* `alg` (required): fixed by the type of the client's key:

  | Key type | `alg` |
  |----------|-------|
  | Ed25519 | `ed25519` |
  | ECDSA P-256 | `ecdsa-p256-sha256` (signature is raw `r‖s`) |
  | RSA, at least 2048 bits | `rsa-pss-sha512` (salt length 64) |

* `nonce` (optional): if present, it is accepted only once.

`@authority` is the `Host` header as received and `@path` is the request
path. A reverse proxy in front of the server must not change either.

## Responses

| Status | Meaning |
|--------|---------|
| 200 | Done. The body echoes the request (acme.sh's acmeproxy client checks for this). |
| 400 | Malformed body. |
| 401 | Signature, digest, timestamp, nonce or keyid rejected. |
| 403 | The client may not manage this record. |
| 502 | The DNS provider failed. |

Errors have the body `{"error": "<message>"}`.

## Authorization

The server allows `_acme-challenge.<domain>` when the client's `domains` table
has `<domain>` itself, or `*.<parent>` for a parent of `<domain>`. The record
goes into the zone of the registrable domain (`example.com` for
`a.b.example.com`).
