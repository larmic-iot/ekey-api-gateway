package handler

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/larmic-iot/ekey-api-gateway/internal/auth"
	"github.com/larmic-iot/ekey-api-gateway/internal/config"
)

type ProxyHandler struct {
	state  *auth.State
	cfg    config.Config
	client *http.Client
}

func NewProxyHandler(state *auth.State, cfg config.Config) *ProxyHandler {
	return &ProxyHandler{
		state:  state,
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (h *ProxyHandler) Handle(w http.ResponseWriter, r *http.Request) {
	if h.state.Status() != auth.Authenticated {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "not authenticated"})
		return
	}

	// Strip /proxy/ prefix
	targetPath := strings.TrimPrefix(r.URL.Path, "/proxy")
	targetURL := h.cfg.APIBase + targetPath

	// Preserve query parameters, add api-version if not present
	query := r.URL.Query()
	if query.Get("api-version") == "" {
		query.Set("api-version", h.cfg.APIVersion)
	}
	targetURL += "?" + query.Encode()

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		slog.Error("creating proxy request failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	// Copy relevant headers
	for _, key := range []string{"Content-Type", "Accept"} {
		if v := r.Header.Get(key); v != "" {
			proxyReq.Header.Set(key, v)
		}
	}

	// Inject Bearer token
	proxyReq.Header.Set("Authorization", "Bearer "+h.state.AccessToken())
	proxyReq.Header.Set("Accept", "application/json")

	slog.Debug("proxying request", "method", r.Method, "target", targetURL)

	resp, err := h.client.Do(proxyReq)
	if err != nil {
		slog.Error("proxy request failed", "error", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream request failed"})
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
