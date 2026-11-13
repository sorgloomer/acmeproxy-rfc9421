This project contains client and server libraries that implement an acme-proxy
style behavior, but authentication built on top of rfc9421 http signatures.


## AcmeProxy DNS API documentation

The api consists of the following json endpoints:

```
POST $ACMEPROXY_ENDPOINT/present {"fqdn":"$ACMEPROXY_FQDN","value":"$ACMEPROXY_VALUE"}
POST $ACMEPROXY_ENDPOINT/cleanup {"fqdn":"$ACMEPROXY_FQDN","value":"$ACMEPROXY_VALUE"}
```

In addition, timestamp, algo, keyid and signature headerers must be present
as specified in rfc9421

Please do planning and write specific api documentation with specific headers
in docs/api.md .

The system should support at least the following cryptographic protocols:
 - RSA
 - Ed25519
 - ECDSA


## Client

The client should use openssh style pem private keys. The key can be given
either as a file, pointed to by an environment variable, or a variable can
hold the whole key.

```
KEY_ID: the keyid that identifies the client
KEY_PATH: if present, the private key is loaded from this file
KEY_VALUE: if present, parsed as an openssh private key
```

Please place a readme.md in clients/caddy/readme.md and offer an example
on how to build caddy with this plugin using xcaddy.

## Server


The golang server uses libdns for upstream providers.

It offers xcaddy style self-service builds. Place documentation about how to
build it into servers/golang/readme.md .


### Configuration

The configuration is given as toml.

Example TOML:

```
[clients.servera]
pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINwaYvMbbD+xX4pRolIHJjxdhzIKEzsYt6WmXf3btSGH hege@asgard" # ssh style public key, also specifies expected algo for the key
domains = {
  "servicea.example.com": "default",
  "serviceb.example.com": "default",
}

[providers.default]
provider = hetzner
api_key = "abc...xyz"
```


## References

  - [acme.sh acmeproxy client implementation](https://github.com/acmesh-official/acme.sh/blob/master/dnsapi/dns_acmeproxy.sh)
  - [acme.sh acmeproxy documentation](https://github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_acmeproxy)
  - [original acmeproxy server implementation](https://github.com/mdbraber/acmeproxy/)


## Instructions

The human user will later push this project to
https://github.com/sorgloomer/acmeproxy-rfc9421 .
Assume this place when writing documentation and
examples.

 - Place the implementation of a caddy plugin in `clients/caddy`.
 - Place an implementation of a golang based server in `servers/golang`,
   with the functionality described above.
 - Populate a readme.md at the root of the repository.
