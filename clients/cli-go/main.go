// Command cli-go is an acmeproxy-rfc9421 client implementing the
// protocol of lego's "exec" DNS provider:
//
//	cli-go present|cleanup <fqdn> <value>
//
// Traefik and other lego based tools call it through EXEC_PATH, and the
// acmesh-go acme.sh script calls it the same way.
//
// Configuration: ACMEPROXY_ENDPOINT, KEY_ID, KEY_PATH or KEY_VALUE.
package main

import (
	"os"

	shared "github.com/sorgloomer/acmeproxy-rfc9421/lib/golang"
)

func main() {
	os.Exit(shared.RunCLI(os.Args[1:], os.Stdout, os.Stderr))
}
