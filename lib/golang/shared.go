// Package shared holds what the acmeproxy-rfc9421 server and Go clients have
// in common: the RFC 9421 signature profile and a minimal client.
package shared

import (
	"bytes"
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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/yaronf/httpsign"
)

// SignedComponents are the RFC 9421 components every request signature covers.
var SignedComponents = []string{"@method", "@authority", "@path", "content-type", "content-digest"}

// Algorithm returns the RFC 9421 algorithm used with a key, which is fixed by
// the key type.
func Algorithm(pub crypto.PublicKey) (string, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return "ed25519", nil
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			return "ecdsa-p256-sha256", nil
		}
	case *rsa.PublicKey:
		if k.N.BitLen() >= 2048 {
			return "rsa-pss-sha512", nil
		}
	}
	return "", errors.New("unsupported key: use Ed25519, ECDSA P-256 or RSA with at least 2048 bits")
}

// NewVerifier returns a verifier for pub that requires SignedComponents.
func NewVerifier(pub crypto.PublicKey, cfg *httpsign.VerifyConfig) (*httpsign.Verifier, error) {
	fields := httpsign.Headers(SignedComponents...)
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return httpsign.NewEd25519Verifier(k, cfg, fields)
	case *ecdsa.PublicKey:
		return httpsign.NewP256Verifier(*k, cfg, fields)
	case *rsa.PublicKey:
		return httpsign.NewRSAPSSVerifier(*k, cfg, fields)
	}
	return nil, fmt.Errorf("unsupported key type %T", pub)
}

func newSigner(key crypto.Signer, cfg *httpsign.SignConfig) (*httpsign.Signer, error) {
	fields := httpsign.Headers(SignedComponents...)
	switch k := key.(type) {
	case ed25519.PrivateKey:
		return httpsign.NewEd25519Signer(k, cfg, fields)
	case *ecdsa.PrivateKey:
		return httpsign.NewP256Signer(*k, cfg, fields)
	case *rsa.PrivateKey:
		return httpsign.NewRSAPSSSigner(*k, cfg, fields)
	}
	return nil, fmt.Errorf("unsupported key type %T", key)
}

// Config configures a Client. KeyValue takes precedence over KeyPath; both
// hold a PKCS#8 PEM private key ("BEGIN PRIVATE KEY").
type Config struct {
	Endpoint string // base URL, e.g. https://acmeproxy.example.com
	KeyID    string
	KeyPath  string
	KeyValue string
}

// ConfigFromEnv reads ACMEPROXY_ENDPOINT, KEY_ID, KEY_PATH and KEY_VALUE.
func ConfigFromEnv() Config {
	return Config{
		Endpoint: os.Getenv("ACMEPROXY_ENDPOINT"),
		KeyID:    os.Getenv("KEY_ID"),
		KeyPath:  os.Getenv("KEY_PATH"),
		KeyValue: os.Getenv("KEY_VALUE"),
	}
}

// Client sends signed /present and /cleanup requests.
type Client struct {
	endpoint *url.URL
	keyID    string
	key      crypto.Signer
	http     *http.Client
}

// NewClient validates cfg and loads the private key.
func NewClient(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("endpoint %q must be an http(s) URL (ACMEPROXY_ENDPOINT)", cfg.Endpoint)
	}
	if cfg.KeyID == "" {
		return nil, errors.New("key ID is not set (KEY_ID)")
	}
	keyPEM := []byte(cfg.KeyValue)
	if cfg.KeyValue == "" {
		if cfg.KeyPath == "" {
			return nil, errors.New("no private key configured (KEY_PATH or KEY_VALUE)")
		}
		if keyPEM, err = os.ReadFile(cfg.KeyPath); err != nil {
			return nil, err
		}
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("private key must be PKCS#8 PEM (BEGIN PRIVATE KEY); create one with keygen.sh")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	key, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported key type %T", parsed)
	}
	if _, err := Algorithm(key.Public()); err != nil {
		return nil, err
	}
	return &Client{
		endpoint: u,
		keyID:    cfg.KeyID,
		key:      key,
		// Redirects would change the signed authority or path.
		http: &http.Client{
			Timeout:       2 * time.Minute,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Present asks the server to create the TXT record fqdn with value.
func (c *Client) Present(ctx context.Context, fqdn, value string) error {
	return c.call(ctx, "present", fqdn, value)
}

// Cleanup asks the server to delete the TXT record fqdn with value.
func (c *Client) Cleanup(ctx context.Context, fqdn, value string) error {
	return c.call(ctx, "cleanup", fqdn, value)
}

func (c *Client) call(ctx context.Context, action, fqdn, value string) error {
	fqdn = strings.TrimSuffix(fqdn, ".")
	body, _ := json.Marshal(map[string]string{"fqdn": fqdn, "value": value})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint.JoinPath(action).String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	digest := sha256.Sum256(body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(digest[:])+":")

	signer, err := newSigner(c.key, httpsign.NewSignConfig().SetKeyID(c.keyID).SetNonce(rand.Text()))
	if err != nil {
		return err
	}
	sigInput, sig, err := httpsign.SignRequest("sig1", *signer, req)
	if err != nil {
		return err
	}
	req.Header.Set("Signature-Input", sigInput)
	req.Header.Set("Signature", sig)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", action, fqdn, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	var e struct{ Error string }
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if json.Unmarshal(respBody, &e) != nil || e.Error == "" {
		e.Error = strings.TrimSpace(string(respBody))
	}
	return fmt.Errorf("%s %s: HTTP %d: %s", action, fqdn, resp.StatusCode, e.Error)
}

// RunCLI implements "present|cleanup <fqdn> <value>" (the lego exec protocol)
// with configuration from the environment, and returns an exit code.
func RunCLI(args []string, stdout, stderr io.Writer) int {
	if len(args) != 3 || (args[0] != "present" && args[0] != "cleanup") {
		fmt.Fprintln(stderr, "usage: present|cleanup <fqdn> <value>  (env: ACMEPROXY_ENDPOINT, KEY_ID, KEY_PATH or KEY_VALUE)")
		return 2
	}
	c, err := NewClient(ConfigFromEnv())
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if args[0] == "present" {
			err = c.Present(ctx, args[1], args[2])
		} else {
			err = c.Cleanup(ctx, args[1], args[2])
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "acmeproxy:", err)
		return 1
	}
	fmt.Fprintf(stdout, "acmeproxy: %s %s: ok\n", args[0], args[1])
	return 0
}
