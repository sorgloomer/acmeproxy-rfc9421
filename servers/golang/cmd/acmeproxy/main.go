// Command acmeproxy is the default acmeproxy-rfc9421 server build, with a
// small set of libdns providers compiled in. Use xacmeproxy to build a
// binary with the providers you need.
package main

import (
	"github.com/libdns/cloudflare"
	"github.com/libdns/hetzner/v2"

	"github.com/sorgloomer/acmeproxy-rfc9421/servers/golang/server"
)

func main() {
	server.RegisterProvider("cloudflare", func() any { return new(cloudflare.Provider) })
	server.RegisterProvider("hetzner", func() any { return new(hetzner.Provider) })
	server.Main()
}
