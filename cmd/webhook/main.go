// Command webhook is the external-dns webhook provider for Nubulus DNS.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	nubulus "github.com/nubulus-network/nubulus-go"

	"github.com/nubulus-network/external-dns-webhook/internal/provider"
	"github.com/nubulus-network/external-dns-webhook/internal/webhook"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel()}))
	if err := run(logger); err != nil {
		logger.Error("exiting", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Only the credential is required. The endpoints, the token URL and the
	// project are compiled into nubulus-go and the variables exist for tests.
	client, err := nubulus.New(ctx, nubulus.Config{
		ClientID:     os.Getenv("NUBULUS_CLIENT_ID"),
		ClientSecret: os.Getenv("NUBULUS_CLIENT_SECRET"),
		TokenURL:     os.Getenv("NUBULUS_TOKEN_URL"),
		ProjectID:    os.Getenv("NUBULUS_PROJECT_ID"),
		DNSEndpoint:  os.Getenv("NUBULUS_DNS_ENDPOINT"),
		UserAgent:    "external-dns-webhook/" + version,
	})
	if err != nil {
		return err
	}

	p := provider.New(client.DNS, logger)
	permanent := func(err error) bool { return errors.Is(err, provider.ErrPermanent) }

	api := &http.Server{
		Addr:              env("WEBHOOK_LISTEN", "127.0.0.1:8888"),
		Handler:           webhook.NewHandler(p, permanent, logger),
		ReadHeaderTimeout: 10 * time.Second,
	}
	health := &http.Server{
		Addr:              env("HEALTH_LISTEN", "0.0.0.0:8080"),
		Handler:           webhook.NewHealthHandler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errc := make(chan error, 2)
	for _, srv := range []*http.Server{api, health} {
		go func() {
			logger.Info("listening", "addr", srv.Addr, "version", version)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}

	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = api.Shutdown(shutdownCtx)
	_ = health.Shutdown(shutdownCtx)
	return nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func logLevel() slog.Level {
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}
