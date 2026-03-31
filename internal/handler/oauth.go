package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/larmic-iot/ekey-api-gateway/internal/auth"
)

type OAuthHandler struct {
	oauth *auth.OAuthClient
	state *auth.State
}

func NewOAuthHandler(oauth *auth.OAuthClient, state *auth.State) *OAuthHandler {
	return &OAuthHandler{oauth: oauth, state: state}
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Login performs the full Azure AD B2C login flow with the provided credentials.
// POST /oauth/login {"email": "...", "password": "..."}
func (h *OAuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body, expected {\"email\": \"...\", \"password\": \"...\"}"})
		return
	}

	if req.Email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email and password are required"})
		return
	}

	slog.Info("starting login")

	tokenResp, err := h.oauth.LoginWithCredentials(req.Email, req.Password)
	if err != nil {
		slog.Error("login failed", "error", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "login failed"})
		return
	}

	slog.Info("login successful", "expires_in", tokenResp.ExpiresIn)

	writeJSON(w, http.StatusOK, map[string]any{
		"message":    "login successful",
		"token_type": tokenResp.TokenType,
		"expires_in": tokenResp.ExpiresIn,
	})
}

type callbackRequest struct {
	RedirectURL string `json:"redirect_url"`
}

// Callback accepts the redirect URL from a manual browser-based login flow (fallback).
// POST /oauth/callback {"redirect_url": "msal...?code=XXX"}
func (h *OAuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
	var req callbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body, expected {\"redirect_url\": \"msal...?code=XXX\"}"})
		return
	}

	if req.RedirectURL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "redirect_url is required"})
		return
	}

	parsed, err := url.Parse(req.RedirectURL)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid URL: " + err.Error()})
		return
	}

	code := parsed.Query().Get("code")
	if code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no 'code' parameter found in redirect URL"})
		return
	}

	state := parsed.Query().Get("state")
	expectedState := h.state.ExpectedState()
	if expectedState != "" && state != expectedState {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "state parameter mismatch"})
		return
	}

	tokenResp, err := h.oauth.ExchangeCode(code)
	if err != nil {
		slog.Error("code exchange failed", "error", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "code exchange failed"})
		return
	}

	slog.Info("login successful via callback", "expires_in", tokenResp.ExpiresIn)

	writeJSON(w, http.StatusOK, map[string]any{
		"message":    "login successful",
		"token_type": tokenResp.TokenType,
		"expires_in": tokenResp.ExpiresIn,
	})
}

func (h *OAuthHandler) Refresh(w http.ResponseWriter, _ *http.Request) {
	tokenResp, err := h.oauth.RefreshAccessToken()
	if err != nil {
		slog.Error("manual token refresh failed", "error", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "token refresh failed"})
		return
	}

	slog.Info("token refreshed manually", "expires_in", tokenResp.ExpiresIn)

	writeJSON(w, http.StatusOK, map[string]any{
		"message":    "token refreshed",
		"token_type": tokenResp.TokenType,
		"expires_in": tokenResp.ExpiresIn,
	})
}
