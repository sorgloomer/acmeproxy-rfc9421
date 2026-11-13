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
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yaronf/httpsign"
)

func pkcs8(t *testing.T, key crypto.Signer) string {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestClientSignaturesVerify(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	for _, key := range []crypto.Signer{ed, p256, rsaKey} {
		alg, _ := Algorithm(key.Public())
		t.Run(alg, func(t *testing.T) {
			verifier, err := NewVerifier(key.Public(), httpsign.NewVerifyConfig().SetKeyID("c").SetAllowedAlgs([]string{alg}))
			if err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				rc := io.NopCloser(bytes.NewReader(body))
				if err := httpsign.VerifyRequest("sig1", *verifier, r); err != nil {
					http.Error(w, `{"error":"`+err.Error()+`"}`, 401)
				} else if err := httpsign.ValidateContentDigestHeader(r.Header.Values("Content-Digest"), &rc, []string{"sha-256"}); err != nil {
					http.Error(w, `{"error":"`+err.Error()+`"}`, 401)
				} else if r.URL.Path != "/acme/present" || !strings.Contains(string(body), `"fqdn":"_acme-challenge.example.com"`) {
					http.Error(w, `{"error":"bad request"}`, 400)
				}
			}))
			defer srv.Close()

			c, err := NewClient(Config{Endpoint: srv.URL + "/acme/", KeyID: "c", KeyValue: pkcs8(t, key)})
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Present(context.Background(), "_acme-challenge.example.com.", "v"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNewClientErrors(t *testing.T) {
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	for want, cfg := range map[string]Config{
		"must be an http(s) URL": {KeyID: "a", KeyValue: pkcs8(t, ed)},
		"key ID is not set":      {Endpoint: "https://x"},
		"no private key":         {Endpoint: "https://x", KeyID: "a"},
		"PKCS#8 PEM":             {Endpoint: "https://x", KeyID: "a", KeyValue: "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"},
		"unsupported key":        {Endpoint: "https://x", KeyID: "a", KeyValue: pkcs8(t, p384)},
	} {
		if _, err := NewClient(cfg); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("got %v, want error containing %q", err, want)
		}
	}
}
