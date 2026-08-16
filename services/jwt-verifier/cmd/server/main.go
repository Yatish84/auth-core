package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Yatish84/auth-core/services/jwt-verifier/internal/httpapi"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	verifier, err := httpapi.NewJWTVerifier(
		environment("JWKS_URL", "http://auth-api:8000/.well-known/jwks.json"),
		environment("JWT_ISSUER", "http://localhost:8000"),
		environment("JWT_AUDIENCE", "grox-platform"),
		environment("REDIS_URL", "redis://redis:6379/0"),
		environment("REDIS_KEY_HMAC_SECRET", "local-development-key-change-me"),
	)
	if err != nil {
		slog.Error("jwt verifier configuration failed", "error", err)
		os.Exit(1)
	}
	defer verifier.Close()

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           httpapi.NewRouter(verifier),
		ReadHeaderTimeout: 5 * time.Second,
	}

	shutdownSignal, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stop()

	go func() {
		slog.Info("jwt verifier listening", "port", port)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("jwt verifier stopped unexpectedly", "error", err)
			os.Exit(1)
		}
	}()

	<-shutdownSignal.Done()

	shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		slog.Error("jwt verifier shutdown failed", "error", err)
		os.Exit(1)
	}
}

func environment(name string, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
