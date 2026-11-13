// Package server implements the acmeproxy-rfc9421 server: POST /present and
// POST /cleanup, authenticated with RFC 9421 signatures, publishing ACME
// challenge TXT records through libdns providers.
package server

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
	"github.com/yaronf/httpsign"
	"golang.org/x/net/publicsuffix"

	shared "github.com/sorgloomer/acmeproxy-rfc9421/lib/golang"
)

const challengePrefix = "_acme-challenge."

var (
	domainRE = regexp.MustCompile(`^[a-z0-9_-]+(\.[a-z0-9_-]+)+$`)
	valueRE  = regexp.MustCompile(`^[A-Za-z0-9_+/=-]{1,255}$`)
)

// Server is the acmeproxy HTTP handler.
type Server struct {
	cfg     *Config
	clients map[string]*client

	mu     sync.Mutex
	nonces map[string]time.Time // keyid+nonce -> expiry
}

type client struct {
	verifier *httpsign.Verifier
	domains  map[string]*provider
}

type provider struct {
	name string
	dns  DNSProvider
	mu   sync.Mutex // many libdns providers do read-modify-write
}

// New validates cfg and instantiates its providers.
func New(cfg *Config) (*Server, error) {
	providers := map[string]*provider{}
	for name, table := range cfg.Providers {
		dns, err := newProvider(name, table)
		if err != nil {
			return nil, fmt.Errorf("providers.%s: %w", name, err)
		}
		providers[name] = &provider{name: name, dns: dns}
	}
	if len(cfg.Clients) == 0 {
		return nil, errors.New("no clients configured")
	}
	s := &Server{cfg: cfg, clients: map[string]*client{}, nonces: map[string]time.Time{}}
	for i, cc := range cfg.Clients {
		domains := map[string]*provider{} // shared by all keys of this entry
		for domain, pname := range cc.Domains {
			if !domainRE.MatchString(strings.TrimPrefix(domain, "*.")) {
				return nil, fmt.Errorf("client[%d]: invalid domain %q", i, domain)
			}
			if domains[domain] = providers[pname]; domains[domain] == nil {
				return nil, fmt.Errorf("client[%d]: domain %q uses undefined provider %q", i, domain, pname)
			}
		}
		if len(cc.Keys) == 0 {
			return nil, fmt.Errorf("client[%d]: no keys", i)
		}
		for keyID, pubkey := range cc.Keys {
			if s.clients[keyID] != nil {
				return nil, fmt.Errorf("client[%d]: keyid %q is used more than once", i, keyID)
			}
			verifier, err := newVerifier(keyID, pubkey, cfg)
			if err != nil {
				return nil, fmt.Errorf("client[%d]: key %q: %w", i, keyID, err)
			}
			s.clients[keyID] = &client{verifier: verifier, domains: domains}
		}
	}
	return s, nil
}

// newVerifier parses a base64 SPKI public key and returns a verifier pinned
// to keyID and the key's algorithm.
func newVerifier(keyID, pubkey string, cfg *Config) (*httpsign.Verifier, error) {
	der, err := base64.StdEncoding.DecodeString(pubkey)
	if err != nil {
		return nil, fmt.Errorf("must be base64 SPKI: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	alg, err := shared.Algorithm(pub)
	if err != nil {
		return nil, err
	}
	return shared.NewVerifier(pub, httpsign.NewVerifyConfig().
		SetKeyID(keyID).
		SetAllowedAlgs([]string{alg}). // makes "alg" mandatory
		SetNotOlderThan(cfg.Server.SignatureExpiration).
		SetNotNewerThan(cfg.Server.ClockDrift))
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	action := path.Base(r.URL.Path) // so the API can live under a path prefix
	if action != "present" && action != "cleanup" {
		writeJSON(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, "reading body: "+err.Error())
		return
	}
	keyID, c, err := s.authenticate(r, body)
	if err != nil {
		slog.Warn("authentication failed", "remote", r.RemoteAddr, "error", err)
		writeJSON(w, http.StatusUnauthorized, err.Error())
		return
	}
	var req struct{ FQDN, Value string }
	if json.Unmarshal(body, &req) != nil || !valueRE.MatchString(req.Value) {
		writeJSON(w, http.StatusBadRequest, "body must be {\"fqdn\": ..., \"value\": <base64url>}")
		return
	}
	p, zone, name, err := c.resolve(req.FQDN)
	if err != nil {
		writeJSON(w, http.StatusForbidden, fmt.Sprintf("client %q: %v", keyID, err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	p.mu.Lock()
	if action == "present" {
		_, err = p.dns.AppendRecords(ctx, zone, []libdns.Record{libdns.TXT{Name: name, TTL: s.cfg.Server.RecordTTL, Text: req.Value}})
	} else { // TTL 0 matches any TTL
		_, err = p.dns.DeleteRecords(ctx, zone, []libdns.Record{libdns.TXT{Name: name, Text: req.Value}})
	}
	p.mu.Unlock()
	if err != nil {
		slog.Error("provider failed", "provider", p.name, "error", err)
		writeJSON(w, http.StatusBadGateway, fmt.Sprintf("provider %q: %v", p.name, err))
		return
	}
	slog.Info(action, "client", keyID, "fqdn", req.FQDN, "provider", p.name)
	// Echoing the request matches what acme.sh's acmeproxy client expects.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"fqdn": req.FQDN, "value": req.Value})
}

// authenticate verifies the first signature of the request and the body digest.
func (s *Server) authenticate(r *http.Request, body []byte) (string, *client, error) {
	names, err := httpsign.RequestSignatureNames(r, false)
	if err != nil || len(names) == 0 {
		return "", nil, errors.New("request is not signed (RFC 9421 Signature-Input and Signature required)")
	}
	details, err := httpsign.RequestDetails(names[0], r)
	if err != nil {
		return "", nil, err
	}
	if details.KeyID == nil || s.clients[*details.KeyID] == nil {
		return "", nil, errors.New("unknown or missing keyid")
	}
	keyID, c := *details.KeyID, s.clients[*details.KeyID]
	if err := httpsign.VerifyRequest(names[0], *c.verifier, r); err != nil {
		return "", nil, err
	}
	rc := io.NopCloser(strings.NewReader(string(body)))
	if err := httpsign.ValidateContentDigestHeader(r.Header.Values("Content-Digest"), &rc,
		[]string{httpsign.DigestSha256, httpsign.DigestSha512}); err != nil {
		return "", nil, fmt.Errorf("Content-Digest: %w", err)
	}
	// The nonce is optional (RFC 9421). It is only recorded after the
	// signature verified, so forged requests cannot burn nonces.
	if details.Nonce != nil && !s.useNonce(keyID+" "+*details.Nonce) {
		return "", nil, errors.New("nonce already used")
	}
	return keyID, c, nil
}

func (s *Server) useNonce(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, exp := range s.nonces {
		if now.After(exp) {
			delete(s.nonces, k)
		}
	}
	if _, seen := s.nonces[key]; seen {
		return false
	}
	s.nonces[key] = now.Add(s.cfg.Server.SignatureExpiration + s.cfg.Server.ClockDrift)
	return true
}

// resolve checks that the client may manage fqdn and returns the provider,
// the zone (the registrable domain) and the record name relative to it.
func (c *client) resolve(fqdn string) (*provider, string, string, error) {
	name := strings.ToLower(strings.TrimSuffix(fqdn, "."))
	domain, ok := strings.CutPrefix(name, challengePrefix)
	if !ok || !domainRE.MatchString(domain) {
		return nil, "", "", fmt.Errorf("%q is not an _acme-challenge record", fqdn)
	}
	p := c.domains[domain]
	for d := domain; p == nil && strings.Contains(d, "."); {
		_, d, _ = strings.Cut(d, ".")
		p = c.domains["*."+d]
	}
	if p == nil {
		return nil, "", "", fmt.Errorf("not allowed to manage %q", domain)
	}
	zone, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return nil, "", "", err
	}
	return p, zone + ".", strings.TrimSuffix(name, "."+zone), nil
}

func writeJSON(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
