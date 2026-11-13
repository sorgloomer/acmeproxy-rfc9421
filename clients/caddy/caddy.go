// Package acmeproxy is the Caddy DNS provider module
// dns.providers.acmeproxy_rfc9421, which solves ACME DNS-01 challenges
// through an acmeproxy-rfc9421 server.
package acmeproxy

import (
	"context"
	"errors"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"

	shared "github.com/sorgloomer/acmeproxy-rfc9421/lib/golang"
)

func init() {
	caddy.RegisterModule(new(Provider))
}

// Provider is a libdns provider for TXT records. Empty settings fall back to
// the ACMEPROXY_ENDPOINT, KEY_ID, KEY_PATH and KEY_VALUE environment variables.
type Provider struct {
	Endpoint string `json:"endpoint,omitempty"`
	KeyID    string `json:"key_id,omitempty"`
	KeyPath  string `json:"key_path,omitempty"`  // PKCS#8 PEM file
	KeyValue string `json:"key_value,omitempty"` // PKCS#8 PEM text

	client *shared.Client
}

// CaddyModule returns the Caddy module information.
func (*Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "dns.providers.acmeproxy_rfc9421", New: func() caddy.Module { return new(Provider) }}
}

// Provision expands placeholders, applies environment fallbacks and loads the key.
func (p *Provider) Provision(caddy.Context) error {
	repl := caddy.NewReplacer()
	env := shared.ConfigFromEnv()
	cfg := shared.Config{
		Endpoint: repl.ReplaceAll(p.Endpoint, ""),
		KeyID:    repl.ReplaceAll(p.KeyID, ""),
		KeyPath:  repl.ReplaceAll(p.KeyPath, ""),
		KeyValue: repl.ReplaceAll(p.KeyValue, ""),
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = env.Endpoint
	}
	if cfg.KeyID == "" {
		cfg.KeyID = env.KeyID
	}
	if cfg.KeyPath == "" && cfg.KeyValue == "" {
		cfg.KeyPath, cfg.KeyValue = env.KeyPath, env.KeyValue
	}
	var err error
	p.client, err = shared.NewClient(cfg)
	return err
}

// AppendRecords publishes TXT records through /present.
func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return p.each(recs, zone, func(fqdn, value string) error { return p.client.Present(ctx, fqdn, value) })
}

// DeleteRecords removes TXT records through /cleanup.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return p.each(recs, zone, func(fqdn, value string) error { return p.client.Cleanup(ctx, fqdn, value) })
}

func (p *Provider) each(recs []libdns.Record, zone string, call func(fqdn, value string) error) ([]libdns.Record, error) {
	if p.client == nil {
		return nil, errors.New("acmeproxy: provider is not provisioned")
	}
	for i, rec := range recs {
		rr := rec.RR()
		if rr.Type != "TXT" {
			return recs[:i], fmt.Errorf("acmeproxy: only TXT records are supported, got %s", rr.Type)
		}
		if err := call(libdns.AbsoluteName(rr.Name, zone), rr.Data); err != nil {
			return recs[:i], fmt.Errorf("acmeproxy: %w", err)
		}
	}
	return recs, nil
}

// UnmarshalCaddyfile parses:
//
//	acmeproxy_rfc9421 [<endpoint>] {
//	    endpoint  <url>
//	    key_id    <id>
//	    key_path  <file>
//	    key_value <pem>
//	}
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // provider name
	d.Args(&p.Endpoint)
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		fields := map[string]*string{"endpoint": &p.Endpoint, "key_id": &p.KeyID, "key_path": &p.KeyPath, "key_value": &p.KeyValue}
		field, ok := fields[d.Val()]
		if !ok {
			return d.Errf("unknown subdirective %q", d.Val())
		}
		if !d.AllArgs(field) {
			return d.ArgErr()
		}
	}
	return nil
}

var (
	_ caddy.Provisioner     = (*Provider)(nil)
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
