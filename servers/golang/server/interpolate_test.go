package server

import (
	"strings"
	"testing"
)

func TestExpand(t *testing.T) {
	t.Setenv("HETZNER_TOKEN", "s3cret")
	t.Setenv("EMPTY", "")
	t.Setenv("TRICKY", "${{ env.HETZNER_TOKEN }} and ${{$}}")
	for in, want := range map[string]string{
		"plain":                    "plain",
		"${{ env.HETZNER_TOKEN }}": "s3cret",
		"${{env.HETZNER_TOKEN}}":   "s3cret",
		"a-${{ env.HETZNER_TOKEN }}-b-${{ env.HETZNER_TOKEN }}": "a-s3cret-b-s3cret",
		"x${{ env.EMPTY }}y":          "xy",
		"${{$}}":                      "${{",
		"${{$}} env.HETZNER_TOKEN }}": "${{ env.HETZNER_TOKEN }}",
		"${{ env.TRICKY }}":           "${{ env.HETZNER_TOKEN }} and ${{$}}", // substituted text stays as is
		"$ { } {{ }} ${ env.X }":      "$ { } {{ }} ${ env.X }",
	} {
		if got, err := expand(in); err != nil || got != want {
			t.Errorf("expand(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for want, in := range map[string]string{
		"HETZNER_NOPE is not set": "${{ env.HETZNER_NOPE }}",
		"unknown expression":      "${{ foo }}",
		"unterminated":            "token ${{ env.HETZNER_TOKEN",
	} {
		if _, err := expand(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("expand(%q): got %v, want error containing %q", in, err, want)
		}
	}
}

func TestParseConfigInterpolates(t *testing.T) {
	t.Setenv("HETZNER_TOKEN", "s3cret")
	t.Setenv("KEY_A", "AAAA")
	cfg, err := ParseConfig(`
[server]
tls_cert = "${{ env.HETZNER_TOKEN }}.pem"

[[client]]
keys = { a = "${{ env.KEY_A }}" }
domains = { "a.example.com" = "hetzner" }

[providers.hetzner]
api_token = "${{ env.HETZNER_TOKEN }}"
nested = { list = ["x-${{ env.KEY_A }}", 5], literal = "${{$}} env.KEY_A }}" }
`)
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Providers["hetzner"]
	nested := p["nested"].(map[string]any)
	if cfg.Server.TLSCert != "s3cret.pem" || cfg.Clients[0].Keys["a"] != "AAAA" || p["api_token"] != "s3cret" ||
		nested["list"].([]any)[0] != "x-AAAA" || nested["list"].([]any)[1] != int64(5) || nested["literal"] != "${{ env.KEY_A }}" {
		t.Fatalf("not interpolated: %+v %+v", cfg.Server, p)
	}

	_, err = ParseConfig("[providers.hetzner]\nnested = { list = [\"${{ env.HETZNER_NOPE }}\"] }\n")
	if err == nil || !strings.Contains(err.Error(), "providers: hetzner: nested: list: [0]: environment variable HETZNER_NOPE is not set") {
		t.Fatalf("got %v", err)
	}
}
