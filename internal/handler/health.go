package handler

import (
	"encoding/json"
	"net/http"

	"github.com/larmic-iot/ekey-api-gateway/internal/auth"
)

type HealthHandler struct {
	state *auth.State
}

func NewHealthHandler(state *auth.State) *HealthHandler {
	return &HealthHandler{state: state}
}

func (h *HealthHandler) Health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "UP"})
}

func (h *HealthHandler) Live(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "UP"})
}

func (h *HealthHandler) Ready(w http.ResponseWriter, _ *http.Request) {
	status := h.state.Status()
	if status == auth.Authenticated {
		writeJSON(w, http.StatusOK, map[string]string{"status": "UP", "auth": status.String()})
		return
	}
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "DOWN", "auth": status.String()})
}

func writeJSON(w http.ResponseWriter, statusCode int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(v)
}
