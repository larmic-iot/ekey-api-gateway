package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/larmic-iot/ekey-api-gateway/internal/auth"
	"github.com/larmic-iot/ekey-api-gateway/internal/client"
	"github.com/larmic-iot/ekey-api-gateway/internal/config"
	"github.com/larmic-iot/ekey-api-gateway/internal/handler"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))

	cfg := config.Load()
	state := auth.NewState()
	oauth := auth.NewOAuthClient(cfg, state)
	mobileClient := client.NewMobileClientService(cfg, state)

	healthHandler := handler.NewHealthHandler(state)
	oauthHandler := handler.NewOAuthHandler(oauth, state)
	proxyHandler := handler.NewProxyHandler(state, cfg)
	infoHandler := handler.NewInfoHandler(state, cfg)

	mux := http.NewServeMux()

	// Health
	mux.HandleFunc("GET /health", healthHandler.Health)
	mux.HandleFunc("GET /health/ready", healthHandler.Ready)
	mux.HandleFunc("GET /health/live", healthHandler.Live)

	// Info
	mux.HandleFunc("GET /info", infoHandler.Info)

	// OAuth
	mux.HandleFunc("POST /oauth/login", oauthHandler.Login)
	mux.HandleFunc("POST /oauth/callback", oauthHandler.Callback)
	mux.HandleFunc("POST /oauth/refresh", oauthHandler.Refresh)

	// Proxy
	mux.HandleFunc("/proxy/", proxyHandler.Handle)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.ServerPort),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Background token refresh
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	refresher := auth.NewRefresher(oauth, state, cfg.TokenRefreshInterval)
	go refresher.Run(ctx)

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		slog.Info("shutting down", "signal", sig)
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		server.Shutdown(shutdownCtx)
	}()

	discovery := client.NewDiscoveryService(cfg, state)

	slog.Info("starting ekey bionyx API gateway", "port", cfg.ServerPort)

	// Auto-login, discovery and MobileClient initialization
	if cfg.Email != "" && cfg.Password != "" {
		slog.Info("auto-login enabled")
		go func() {
			// Step 1: Login
			resp, err := oauth.LoginWithCredentials(cfg.Email, cfg.Password)
			if err != nil {
				slog.Error("auto-login failed", "error", err)
				return
			}
			slog.Info("auto-login successful", "expires_in", resp.ExpiresIn)

			// Step 2: Discover systemID and deviceID from API
			if err := discovery.Discover(); err != nil {
				slog.Error("discovery failed", "error", err)
				return
			}
			slog.Info("discovery complete", "systemId", state.SystemID(), "deviceId", state.DeviceID())

			// Step 3: Load info cache (user, systems, devices)
			if err := infoHandler.Load(); err != nil {
				slog.Error("info load failed", "error", err)
			}

			// Step 4: Initialize MobileClient (load existing or register new)
			if err := mobileClient.Init(); err != nil {
				slog.Error("mobile client initialization failed", "error", err)
				return
			}
			slog.Info("mobile client ready")

			// Step 5: Start periodic info refresh (every 5 minutes)
			go infoHandler.RunRefresh(ctx, 5*time.Minute)
		}()
	} else {
		slog.Info("no credentials configured, use POST /oauth/login to authenticate")
	}

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}

	slog.Info("server stopped")
}
