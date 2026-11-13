This project contains client and server libraries that implement an acme-proxy
style behavior, but authentication built on top of rfc9421 http signatures.


## AcmeProxy DNS API documentation

The api consists of the following json endpoints:

```
POST $ACMEPROXY_ENDPOINT/present {"fqdn":"$ACMEPROXY_FQDN","value":"$ACMEPROXY_VALUE"}
POST $ACMEPROXY_ENDPOINT/cleanup {"fqdn":"$ACMEPROXY_FQDN","value":"$ACMEPROXY_VALUE"}
```

In addition, requests carry the RFC 9421 `Signature-Input` and `Signature`
headers. `Signature-Input` must contain the `created` (timestamp), `alg` and
`keyid` signature parameters.

The specific api documentation, with specific headers, is in docs/api.md.

The system supports at least the following cryptographic protocols:
 - RSA
 - Ed25519
 - ECDSA


## Client

Clients use PKCS#8 PEM private keys, the format that both Go and OpenSSL read
without conversion. The key can be given either as a file, pointed to by an
environment variable, or a variable can hold the whole key.

```
ACMEPROXY_ENDPOINT: the base url of the server
KEY_ID: the keyid that identifies the client
KEY_PATH: if present, the private key is loaded from this file
KEY_VALUE: if present, holds the private key itself
```

Every client contains a keygen.sh that creates a private key in its format and
the matching public key for the server, as base64 DER SubjectPublicKeyInfo (SPKI).

Clients:
 - `clients/caddy`: a caddy plugin. Its readme.md shows how to build caddy with
   it using xcaddy.
 - `clients/cli-go`: a go based client implementing lego's exec dns
   provider protocol.
 - `clients/traefik`: traefik setup, using cli-go through lego's exec
   dns provider.
 - `clients/acmesh-openssl`: an acme.sh dns api script that signs with openssl.
 - `clients/acmesh-go`: an acme.sh dns api script that is a trampoline to
   cli-go.

Code shared by the go programs lives in `lib/golang`.

## Server


The golang server uses libdns for upstream providers.

It offers xcaddy style self-service builds. Documentation about how to build it
is in servers/golang/readme.md .


### Configuration

The configuration is given as toml.

Example TOML:

```toml
# Every key of a [[client]] entry may manipulate every domain of that entry.
[[client]]
keys = { servera = "MCowBQYDK2VwAyEA3Bpi8xtsP7FfilGiUgcmPF2HMgoTOxi3paZd/du1IYc=" } # keyid = base64 SPKI public key of hege@asgard; its type specifies the expected algo
domains = { "servicea.example.com" = "hetzner", "serviceb.example.com" = "hetzner" }

[providers.hetzner] # the provider type defaults to the table name; set provider = "..." to override
api_token = "abc...xyz" # provider settings use the libdns provider's json field names
```


## References

  - [acme.sh acmeproxy client implementation](https://github.com/acmesh-official/acme.sh/blob/master/dnsapi/dns_acmeproxy.sh)
  - [acme.sh acmeproxy documentation](https://github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_acmeproxy)
  - [original acmeproxy server implementation](https://github.com/mdbraber/acmeproxy/)


## Instructions

The project lives at https://github.com/sorgloomer/acmeproxy-rfc9421 .
Documentation and examples assume this place.
