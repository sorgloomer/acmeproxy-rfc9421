package server

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// Main runs the acmeproxy command line. Register providers before calling it.
func Main() {
	defaultPath := os.Getenv("ACMEPROXY_CONFIG_FILE")
	if defaultPath == "" {
		defaultPath = "acmeproxy.toml"
	}
	configPath := flag.String("config", defaultPath, "configuration file (env ACMEPROXY_CONFIG_FILE), unless ACMEPROXY_CONFIG holds the configuration")
	check := flag.Bool("check", false, "validate the configuration and exit")
	list := flag.Bool("list-providers", false, "list the compiled-in DNS providers and exit")
	flag.Parse()
	if *list {
		fmt.Println(strings.Join(RegisteredProviders(), "\n"))
		return
	}
	if err := run(*configPath, *check); err != nil {
		slog.Error("acmeproxy", "error", err)
		os.Exit(1)
	}
}

func run(configPath string, check bool) error {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return err
	}
	srv, err := New(cfg)
	if err != nil {
		return err
	}
	if check {
		fmt.Println("configuration OK")
		return nil
	}

	hs := &http.Server{Addr: cfg.Addr(), Handler: srv, ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = hs.Shutdown(context.Background())
	}()
	slog.Info("acmeproxy listening", "addr", cfg.Addr(), "providers", RegisteredProviders())
	if cfg.Server.TLSCert != "" {
		err = hs.ListenAndServeTLS(cfg.Server.TLSCert, cfg.Server.TLSKey)
	} else {
		err = hs.ListenAndServe()
	}
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
