// Package e2e runs every client against the real server, using keys made by
// each client's keygen.sh. It needs sh, openssl, od and curl.
package e2e

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/libdns/libdns"

	acmeproxy "github.com/sorgloomer/acmeproxy-rfc9421/clients/caddy"
	"github.com/sorgloomer/acmeproxy-rfc9421/servers/golang/server"
)

var repo, _ = filepath.Abs(filepath.Join("..", ".."))

type memory struct {
	mu      sync.Mutex
	records []string
}

var mem = &memory{}

func (m *memory) AppendRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range recs {
		m.records = append(m.records, r.RR().Name+"."+zone+" "+r.RR().Data)
	}
	return recs, nil
}

func (m *memory) DeleteRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range recs {
		m.records = slices.DeleteFunc(m.records, func(s string) bool { return s == r.RR().Name+"."+zone+" "+r.RR().Data })
	}
	return recs, nil
}

func (m *memory) has(record string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Contains(m.records, record)
}

func init() { server.RegisterProvider("memory", func() any { return mem }) }

// harness stands in for acme.sh: _post and _contains mirror acme.sh's
// implementations, account.conf is a directory with one file per value.
const harness = `
_info() { echo "[info] $*"; }
_err() { echo "[error] $*" >&2; }
_contains() { echo "$1" | grep -- "$2" >/dev/null 2>&1; }
_readaccountconf_mutable() { if [ -f "$ACCOUNT/$1" ]; then cat "$ACCOUNT/$1"; fi; }
_saveaccountconf_mutable() { printf "%s" "$2" >"$ACCOUNT/$1"; }
_post() { curl --silent -X "$4" -H "Content-Type: $5" -H "$_H1" -H "$_H2" -H "$_H3" -H "$_H4" -H "$_H5" --data "$1" "$2"; }
. "$SCRIPT"
"dns_acmeproxy_rfc9421_$1" "$2" "$3"
`

type env struct {
	t      *testing.T
	sh     string
	dir    string
	server string
}

func (e *env) run(dir string, environ []string, name string, args ...string) string {
	e.t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), environ...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		e.t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// keygen runs clients/<client>/keygen.sh and returns the private key path and
// the base64 SPKI public key.
func (e *env) keygen(client, keyName string, args ...string) (string, string) {
	e.t.Helper()
	e.run(e.dir, nil, e.sh, append([]string{filepath.ToSlash(filepath.Join(repo, "clients", client, "keygen.sh"))}, args...)...)
	host := strings.TrimSpace(e.run(e.dir, nil, e.sh, "-c", "uname -n"))
	base := filepath.Join(e.dir, keyName+"-"+host) // keygen.sh appends the hostname
	pub, err := os.ReadFile(base + ".pub")
	if err != nil {
		e.t.Fatal(err)
	}
	return filepath.ToSlash(base + ".pem"), strings.TrimSpace(string(pub))
}

func (e *env) goBuild(pkg string) string {
	bin := filepath.Join(e.dir, filepath.Base(pkg))
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	e.run(repo, nil, "go", "build", "-o", bin, "./"+pkg)
	return filepath.ToSlash(bin)
}

// acmesh runs an acme.sh DNS API script; vars are the only configuration
// it sees, plus the saved account configuration in account.
func (e *env) acmesh(client, account string, vars []string, action, fqdn string) {
	e.t.Helper()
	hp := filepath.Join(e.dir, "harness.sh")
	_ = os.WriteFile(hp, []byte(harness), 0o644)
	environ := append([]string{"ACMEPROXY_ENDPOINT=", "KEY_ID=", "KEY_PATH=", "KEY_VALUE=",
		"SCRIPT=" + filepath.ToSlash(filepath.Join(repo, "clients", client, "dns_acmeproxy_rfc9421.sh")),
		"ACCOUNT=" + filepath.ToSlash(account)}, vars...)
	e.run(e.dir, environ, e.sh, filepath.ToSlash(hp), action, fqdn, "token")
}

func findShell(t *testing.T) string {
	for _, sh := range []string{os.Getenv("ACMEPROXY_TEST_SH"), "sh", `C:\Program Files\Git\bin\sh.exe`} {
		if sh == "" {
			continue
		}
		if p, err := exec.LookPath(sh); err == nil && exec.Command(p, "-c", "command -v openssl && command -v od && command -v curl").Run() == nil {
			return p
		}
	}
	t.Skip("needs sh with openssl, od and curl (set ACMEPROXY_TEST_SH)")
	return ""
}

func TestClients(t *testing.T) {
	e := &env{t: t, sh: findShell(t), dir: t.TempDir()}

	type client struct{ name, keygenDir, keyPath, pubkey string }
	var clients []*client
	add := func(name, dir string, args ...string) *client {
		c := &client{name: name, keygenDir: dir}
		c.keyPath, c.pubkey = e.keygen(dir, args[len(args)-1], args...)
		clients = append(clients, c)
		return c
	}
	caddyC := add("caddy", "caddy", "ed25519", "caddy")
	traefik := add("traefik", "traefik", "ecdsa", "traefik")
	goC := add("acmeshgo", "acmesh-go", "rsa", "acmeshgo")
	osslEd := add("opensslEd", "acmesh-openssl", "ed25519", "opensslEd")
	osslEC := add("opensslEC", "acmesh-openssl", "ecdsa", "opensslEC")
	osslRSA := add("opensslRSA", "acmesh-openssl", "rsa", "opensslRSA")

	var cfg strings.Builder
	for _, c := range clients {
		fmt.Fprintf(&cfg, "[[client]]\nkeys = { %s = %q }\ndomains = { \"%s.example.com\" = \"memory\" }\n", c.name, c.pubkey, strings.ToLower(c.name))
	}
	cfg.WriteString("[providers.memory]\n") // the provider type defaults to the table name
	parsed, err := server.ParseConfig(cfg.String())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(parsed)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	record := func(c *client) string { return "_acme-challenge." + strings.ToLower(c.name) + ".example.com. token" }
	fqdn := func(c *client) string { return "_acme-challenge." + strings.ToLower(c.name) + ".example.com" }
	check := func(c *client, present bool) {
		t.Helper()
		if mem.has(record(c)) != present {
			t.Fatalf("%s: record present = %v, want %v (records: %q)", c.name, !present, present, mem.records)
		}
	}
	keyVars := func(c *client) []string {
		return []string{"ACMEPROXY_ENDPOINT=" + ts.URL, "KEY_ID=" + c.name, "KEY_PATH=" + c.keyPath}
	}

	t.Run("caddy", func(t *testing.T) {
		p := &acmeproxy.Provider{Endpoint: ts.URL, KeyID: caddyC.name, KeyPath: caddyC.keyPath}
		if err := p.Provision(caddy.Context{}); err != nil {
			t.Fatal(err)
		}
		recs := []libdns.Record{libdns.TXT{Name: "_acme-challenge.caddy", Text: "token"}}
		if _, err := p.AppendRecords(context.Background(), "example.com.", recs); err != nil {
			t.Fatal(err)
		}
		check(caddyC, true)
		if _, err := p.DeleteRecords(context.Background(), "example.com.", recs); err != nil {
			t.Fatal(err)
		}
		check(caddyC, false)
	})

	t.Run("traefik", func(t *testing.T) {
		bin := e.goBuild("clients/cli-go")
		e.run(e.dir, keyVars(traefik), bin, "present", fqdn(traefik)+".", "token")
		check(traefik, true)
		e.run(e.dir, keyVars(traefik), bin, "cleanup", fqdn(traefik)+".", "token")
		check(traefik, false)
	})

	t.Run("acmesh-go", func(t *testing.T) {
		bin := e.goBuild("clients/cli-go")
		account := t.TempDir()
		e.acmesh("acmesh-go", account, append(keyVars(goC), "ACMEPROXY_BIN="+bin), "add", fqdn(goC))
		check(goC, true)
		e.acmesh("acmesh-go", account, nil, "rm", fqdn(goC)) // renewal: saved configuration only
		check(goC, false)
	})

	t.Run("acmesh-openssl", func(t *testing.T) {
		for _, c := range []*client{osslEd, osslEC, osslRSA} {
			account := t.TempDir()
			vars := keyVars(c)
			if c == osslEC { // KEY_VALUE instead of KEY_PATH
				pemText, _ := os.ReadFile(c.keyPath)
				vars = []string{"ACMEPROXY_ENDPOINT=" + ts.URL + "/", "KEY_ID=" + c.name, "KEY_VALUE=" + string(pemText)}
			}
			e.acmesh("acmesh-openssl", account, vars, "add", fqdn(c))
			check(c, true)
			e.acmesh("acmesh-openssl", account, nil, "rm", fqdn(c))
			check(c, false)
		}
	})

}
