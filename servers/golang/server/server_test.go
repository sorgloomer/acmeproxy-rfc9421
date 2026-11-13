package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/yaronf/httpsign"

	shared "github.com/sorgloomer/acmeproxy-rfc9421/lib/golang"
)

type fakeProvider struct {
	mu      sync.Mutex
	records []string // "zone name value"
}

func (p *fakeProvider) AppendRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range recs {
		p.records = append(p.records, zone+" "+r.RR().Name+" "+r.RR().Data)
	}
	return recs, nil
}

func (p *fakeProvider) DeleteRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range recs {
		p.records = slices.DeleteFunc(p.records, func(s string) bool { return s == zone+" "+r.RR().Name+" "+r.RR().Data })
	}
	return recs, nil
}

func init() { RegisterProvider("fake", func() any { return new(fakeProvider) }) }

func spki(t *testing.T, key crypto.Signer) string {
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// newServer puts all keys, named c0, c1, ..., into one [[client]] entry for
// a.example.com and *.wild.example.org. A second entry lets the returned key,
// named "b", manage b.example.com. The provider type defaults to its name.
func newServer(t *testing.T, keys ...crypto.Signer) (*Server, *fakeProvider, ed25519.PrivateKey) {
	var b strings.Builder
	b.WriteString("[[client]]\nkeys = {")
	for i, k := range keys {
		fmt.Fprintf(&b, " c%d = %q,", i, spki(t, k))
	}
	b.WriteString(" }\ndomains = { \"a.example.com\" = \"fake\", \"*.wild.example.org\" = \"fake\" }\n")
	_, bKey, _ := ed25519.GenerateKey(rand.Reader)
	fmt.Fprintf(&b, "[[client]]\nkeys = { b = %q }\ndomains = { \"b.example.com\" = \"fake\" }\n", spki(t, bKey))
	b.WriteString("[providers.fake]\n")
	cfg, err := ParseConfig(b.String())
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s, s.clients["c0"].domains["a.example.com"].dns.(*fakeProvider), bKey
}

func TestPresentAndCleanup(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	s, fake, _ := newServer(t, ed, p256, rsaKey)
	ts := httptest.NewServer(s)
	defer ts.Close()

	for i, key := range []crypto.Signer{ed, p256, rsaKey} {
		der, _ := x509.MarshalPKCS8PrivateKey(key)
		c, err := shared.NewClient(shared.Config{Endpoint: ts.URL, KeyID: fmt.Sprintf("c%d", i),
			KeyValue: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		if err := c.Present(ctx, "_acme-challenge.a.example.com.", "token"); err != nil {
			t.Fatal(err)
		}
		if err := c.Present(ctx, "_acme-challenge.x.y.wild.example.org", "token"); err != nil {
			t.Fatal(err)
		}
		want := []string{"example.com. _acme-challenge.a token", "example.org. _acme-challenge.x.y.wild token"}
		if !slices.Equal(fake.records, want) {
			t.Fatalf("records %q, want %q", fake.records, want)
		}
		_ = c.Cleanup(ctx, "_acme-challenge.a.example.com", "token")
		_ = c.Cleanup(ctx, "_acme-challenge.x.y.wild.example.org", "token")
		if len(fake.records) != 0 {
			t.Fatalf("records left after cleanup: %q", fake.records)
		}
	}
}

// signed builds a request signed without a nonce,
// or with the given one.
func signed(t *testing.T, key ed25519.PrivateKey, keyID, nonce, path, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "http://acmeproxy.test"+path, strings.NewReader(body))
	sum := sha256.Sum256([]byte(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(sum[:])+":")
	cfg := httpsign.NewSignConfig().SetKeyID(keyID)
	if nonce != "" {
		cfg.SetNonce(nonce)
	}
	signer, _ := httpsign.NewEd25519Signer(key, cfg, httpsign.Headers(shared.SignedComponents...))
	sigInput, sig, err := httpsign.SignRequest("sig1", *signer, r)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Signature-Input", sigInput)
	r.Header.Set("Signature", sig)
	return r
}

func TestRequests(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	s, _, bKey := newServer(t, key)
	body := func(fqdn string) string { return `{"fqdn":"` + fqdn + `","value":"token"}` }
	ok := body("_acme-challenge.a.example.com")

	tampered := signed(t, key, "c0", "", "/present", ok)
	tampered.Body = http.NoBody
	unsigned := signed(t, key, "c0", "", "/present", ok)
	unsigned.Header.Del("Signature")
	unsigned.Header.Del("Signature-Input")
	replayed := func() *http.Request { return signed(t, key, "c0", "same-nonce", "/present", ok) }

	for _, c := range []struct {
		name   string
		req    *http.Request
		status int
	}{
		{"no nonce", signed(t, key, "c0", "", "/present", ok), 200},
		{"path prefix", signed(t, key, "c0", "", "/acme/present", ok), 200},
		{"with nonce", replayed(), 200},
		{"replayed nonce", replayed(), 401},
		{"unsigned", unsigned, 401},
		{"unknown keyid", signed(t, key, "nobody", "", "/present", ok), 401},
		{"wrong key", signed(t, other, "c0", "", "/present", ok), 401},
		{"tampered body", tampered, 401},
		{"other entry's domain", signed(t, key, "c0", "", "/present", body("_acme-challenge.b.example.com")), 403},
		{"key of other entry", signed(t, bKey, "b", "", "/present", ok), 403},
		{"key of other entry, own domain", signed(t, bKey, "b", "", "/present", body("_acme-challenge.b.example.com")), 200},
		{"wildcard parent", signed(t, key, "c0", "", "/present", body("_acme-challenge.wild.example.org")), 403},
		{"not a challenge", signed(t, key, "c0", "", "/present", body("a.example.com")), 403},
		{"bad value", signed(t, key, "c0", "", "/present", `{"fqdn":"_acme-challenge.a.example.com","value":"a\"b"}`), 400},
		{"unknown endpoint", signed(t, key, "c0", "", "/delete", ok), 404},
	} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, c.req)
		if w.Code != c.status {
			t.Errorf("%s: status %d, want %d: %s", c.name, w.Code, c.status, w.Body)
		}
	}
}

func TestConfigErrors(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	client := func(pub, domains string) string {
		return fmt.Sprintf("[[client]]\nkeys = { a = %q }\ndomains = { %s }\n[providers.p]\nprovider = \"fake\"\n", pub, domains)
	}
	for want, cfg := range map[string]string{
		"unknown configuration key": "[server]\nlisten_addr = \":1\"",
		"base64 SPKI":               client("not base64!", `"a.com" = "p"`),
		`key "a"`:                   client("AAAA", `"a.com" = "p"`),
		"no keys":                   "[[client]]\ndomains = { \"a.com\" = \"p\" }\n[providers.p]\nprovider = \"fake\"\n",
		"used more than once":       client(spki(t, key), `"a.com" = "p"`) + "[[client]]\nkeys = { a = \"" + spki(t, key) + "\" }\n",
		`unknown provider type "q"`: client(spki(t, key), `"a.com" = "q"`) + "[providers.q]\n",
		"unsupported key":           client(spki(t, p384), `"a.com" = "p"`),
		"undefined provider":        client(spki(t, key), `"a.com" = "q"`),
		"invalid domain":            client(spki(t, key), `"a..com" = "p"`),
		"unknown field":             client(spki(t, key), `"a.com" = "p"`) + "api_key = \"x\"\n",
		"no clients":                "",
	} {
		cfg, err := ParseConfig(cfg)
		if err == nil {
			_, err = New(cfg)
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("got %v, want error containing %q", err, want)
		}
	}
}

func TestServerSettings(t *testing.T) {
	cfg, err := ParseConfig("")
	if err != nil || cfg.Addr() != ":9095" || cfg.Server.SignatureExpiration != 5*time.Minute || cfg.Server.ClockDrift != 30*time.Second {
		t.Fatalf("defaults: %+v, %v", cfg.Server, err)
	}

	const file = "[server]\nbind = \"127.0.0.1\"\nport = 8000\nsignature_expiration = \"1m\"\nclock_drift = \"5s\"\n"
	if cfg, _ := ParseConfig(file); cfg.Addr() != "127.0.0.1:8000" || cfg.Server.SignatureExpiration != time.Minute || cfg.Server.ClockDrift != 5*time.Second {
		t.Fatalf("from file: %+v", cfg.Server)
	}

	// The environment wins over the file; an empty ACMEPROXY_BIND means all interfaces.
	t.Setenv("ACMEPROXY_BIND", "")
	t.Setenv("ACMEPROXY_PORT", "9000")
	t.Setenv("ACMEPROXY_SIGNATURE_EXPIRATION", "2m")
	t.Setenv("ACMEPROXY_CLOCK_DRIFT", "10s")
	if cfg, _ := ParseConfig(file); cfg.Addr() != ":9000" || cfg.Server.SignatureExpiration != 2*time.Minute || cfg.Server.ClockDrift != 10*time.Second {
		t.Fatalf("from environment: %+v", cfg.Server)
	}

	for name, value := range map[string]string{"ACMEPROXY_PORT": "70000", "ACMEPROXY_CLOCK_DRIFT": "ten seconds"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, value)
			if _, err := ParseConfig(file); err == nil {
				t.Fatalf("%s=%s: expected an error", name, value)
			}
		})
	}
}

func TestLoadConfigFromEnvironment(t *testing.T) {
	missing := t.TempDir() + "/missing.toml"
	if _, err := LoadConfig(missing); err == nil {
		t.Fatal("expected an error for a missing file")
	}
	t.Setenv("ACMEPROXY_CONFIG", "[server]\nport = 7000\n")
	cfg, err := LoadConfig(missing)
	if err != nil || cfg.Server.Port != 7000 {
		t.Fatalf("ACMEPROXY_CONFIG: %+v, %v", cfg, err)
	}
	t.Setenv("ACMEPROXY_CONFIG_FILE", missing)
	if _, err := LoadConfig(missing); err == nil || !strings.Contains(err.Error(), "use only one") {
		t.Fatalf("both set: got %v", err)
	}
}
