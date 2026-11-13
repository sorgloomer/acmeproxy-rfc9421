package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/libdns/libdns"
)

// Config is the TOML configuration file.
type Config struct {
	Server struct {
		Bind                string        `toml:"bind"` // empty: all interfaces
		Port                int           `toml:"port"`
		TLSCert             string        `toml:"tls_cert"`
		TLSKey              string        `toml:"tls_key"`
		SignatureExpiration time.Duration `toml:"signature_expiration"` // max age of "created"
		ClockDrift          time.Duration `toml:"clock_drift"`          // how far "created" may be in the future
		RecordTTL           time.Duration `toml:"record_ttl"`
	} `toml:"server"`
	Clients map[string]struct {
		PubKey  string            `toml:"pubkey"`  // base64 DER SubjectPublicKeyInfo (SPKI)
		Domains map[string]string `toml:"domains"` // domain or *.domain -> provider name
	} `toml:"clients"`
	// Each provider table has a "provider" key naming the libdns provider
	// type; the other keys are its settings, named after its JSON tags.
	Providers map[string]map[string]any `toml:"providers"`
}

// ParseConfig parses a TOML configuration, rejecting unknown keys. The
// ACMEPROXY_BIND, ACMEPROXY_PORT, ACMEPROXY_SIGNATURE_EXPIRATION and
// ACMEPROXY_CLOCK_DRIFT environment variables take precedence over the file.
func ParseConfig(data string) (*Config, error) {
	var cfg Config
	md, err := toml.Decode(data, &cfg)
	if err != nil {
		return nil, err
	}
	for _, k := range md.Undecoded() {
		if k[0] != "providers" {
			return nil, fmt.Errorf("unknown configuration key %q", k.String())
		}
	}

	s := &cfg.Server
	if v, ok := os.LookupEnv("ACMEPROXY_BIND"); ok {
		s.Bind = v
	}
	if v := os.Getenv("ACMEPROXY_PORT"); v != "" {
		if s.Port, err = strconv.Atoi(v); err != nil {
			return nil, fmt.Errorf("ACMEPROXY_PORT: %w", err)
		}
	}
	for name, d := range map[string]*time.Duration{
		"ACMEPROXY_SIGNATURE_EXPIRATION": &s.SignatureExpiration,
		"ACMEPROXY_CLOCK_DRIFT":          &s.ClockDrift,
	} {
		if v := os.Getenv(name); v != "" {
			if *d, err = time.ParseDuration(v); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
		}
	}

	if s.Port == 0 {
		s.Port = 9095
	}
	if s.Port < 1 || s.Port > 65535 {
		return nil, fmt.Errorf("port %d is out of range", s.Port)
	}
	if s.SignatureExpiration == 0 {
		s.SignatureExpiration = 5 * time.Minute
	}
	if s.ClockDrift == 0 {
		s.ClockDrift = 30 * time.Second
	}
	if s.RecordTTL == 0 {
		s.RecordTTL = time.Minute
	}
	return &cfg, nil
}

// Addr is the listen address built from bind and port.
func (c *Config) Addr() string {
	return net.JoinHostPort(c.Server.Bind, strconv.Itoa(c.Server.Port))
}

// LoadConfig reads the configuration from the ACMEPROXY_CONFIG environment
// variable, which holds the TOML itself, or else from the file at path
// (which Main defaults to ACMEPROXY_CONFIG_FILE).
func LoadConfig(path string) (*Config, error) {
	data, source := os.Getenv("ACMEPROXY_CONFIG"), "ACMEPROXY_CONFIG"
	if data != "" && os.Getenv("ACMEPROXY_CONFIG_FILE") != "" {
		return nil, fmt.Errorf("both ACMEPROXY_CONFIG and ACMEPROXY_CONFIG_FILE are set; use only one")
	}
	if data == "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		data, source = string(raw), path
	}
	cfg, err := ParseConfig(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	return cfg, nil
}

// DNSProvider is what acmeproxy needs from a libdns provider.
type DNSProvider interface {
	libdns.RecordAppender
	libdns.RecordDeleter
}

var registry = map[string]func() any{}

// RegisterProvider makes a libdns provider type available to configuration
// files. factory returns a new provider, e.g. func() any { return new(hetzner.Provider) }.
// Call it before Main.
func RegisterProvider(name string, factory func() any) {
	registry[name] = factory
}

// RegisteredProviders returns the registered provider type names.
func RegisteredProviders() []string {
	var names []string
	for name := range registry {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// newProvider instantiates a provider from its TOML table. libdns providers
// describe their settings with JSON tags, so the table goes through JSON.
func newProvider(table map[string]any) (DNSProvider, error) {
	typ, _ := table["provider"].(string)
	factory, ok := registry[typ]
	if !ok {
		return nil, fmt.Errorf("unknown provider type %q (available: %s)", typ, strings.Join(RegisteredProviders(), ", "))
	}
	settings := map[string]any{}
	for k, v := range table {
		if k != "provider" {
			settings[k] = v
		}
	}
	raw, _ := json.Marshal(settings)
	instance := factory()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(instance); err != nil {
		return nil, fmt.Errorf("%s settings: %w", typ, err)
	}
	p, ok := instance.(DNSProvider)
	if !ok {
		return nil, fmt.Errorf("%s does not implement libdns.RecordAppender and RecordDeleter", typ)
	}
	return p, nil
}
