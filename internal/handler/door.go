package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/larmic-iot/ekey-api-gateway/internal/client"
)

type DoorHandler struct {
	doorService *client.DoorService
}

func NewDoorHandler(doorService *client.DoorService) *DoorHandler {
	return &DoorHandler{doorService: doorService}
}

// Open handles POST /door/open requests.
func (h *DoorHandler) Open(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if !h.doorService.Ready() {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error":  "door opening not available",
			"reason": h.doorService.ReadyReason(),
		})
		return
	}

	if err := h.doorService.Open(); err != nil {
		slog.Error("door open failed", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	})
}

// Status handles GET /door/status requests.
func (h *DoorHandler) Status(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"ready":  h.doorService.Ready(),
		"reason": h.doorService.ReadyReason(),
	})
}
