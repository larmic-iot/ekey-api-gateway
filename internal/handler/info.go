package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/larmic-iot/ekey-api-gateway/internal/auth"
	"github.com/larmic-iot/ekey-api-gateway/internal/config"
)

type InfoHandler struct {
	state  *auth.State
	cfg    config.Config
	client *http.Client
}

func NewInfoHandler(state *auth.State, cfg config.Config) *InfoHandler {
	return &InfoHandler{
		state:  state,
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (h *InfoHandler) Info(w http.ResponseWriter, _ *http.Request) {
	if h.state.Status() != auth.Authenticated {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "not authenticated"})
		return
	}

	userAndSystems, err := h.fetchUserAndSystems()
	if err != nil {
		slog.Error("fetching user and systems failed", "error", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "failed to fetch user info"})
		return
	}

	systems := make([]map[string]any, 0, len(userAndSystems.UserSystems))
	for _, sys := range userAndSystems.UserSystems {
		devices, err := h.fetchDevices(sys.SystemID)
		if err != nil {
			slog.Error("fetching devices failed", "systemId", sys.SystemID, "error", err)
			devices = nil
		}

		deviceList := make([]map[string]any, 0, len(devices))
		for _, d := range devices {
			deviceList = append(deviceList, map[string]any{
				"id":   d.ID,
				"name": d.Name,
			})
		}

		systems = append(systems, map[string]any{
			"systemId":  sys.SystemID,
			"created":   sys.Created,
			"onboarded": sys.Onboarded,
			"devices":   deviceList,
		})
	}

	response := map[string]any{
		"auth": map[string]any{
			"status":    h.state.Status().String(),
			"expiresIn": int(h.state.ExpiresIn().Seconds()),
		},
		"user": map[string]any{
			"userId":      userAndSystems.User.UserID,
			"displayName": userAndSystems.User.DisplayName,
			"email":       userAndSystems.User.Email,
		},
		"systems": systems,
	}

	writeJSON(w, http.StatusOK, response)
}

type userAndSystemsResponse struct {
	User struct {
		UserID      string `json:"userId"`
		DisplayName string `json:"displayName"`
		Email       string `json:"email"`
	} `json:"user"`
	UserSystems []struct {
		SystemID  string `json:"systemId"`
		Created   string `json:"created"`
		Onboarded bool   `json:"onboarded"`
	} `json:"userSystems"`
}

func (h *InfoHandler) fetchUserAndSystems() (*userAndSystemsResponse, error) {
	url := fmt.Sprintf("%s/api/User/UserAndSystems?api-version=%s", h.cfg.APIBase, h.cfg.APIVersion)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+h.state.AccessToken())
	req.Header.Set("Accept", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned %d", resp.StatusCode)
	}

	var result userAndSystemsResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

type deviceOverviewEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (h *InfoHandler) fetchDevices(systemID string) ([]deviceOverviewEntry, error) {
	url := fmt.Sprintf("%s/api/System/%s/Device/overview?api-version=%s", h.cfg.APIBase, systemID, h.cfg.APIVersion)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+h.state.AccessToken())
	req.Header.Set("Accept", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned %d", resp.StatusCode)
	}

	var devices []deviceOverviewEntry
	if err := json.Unmarshal(body, &devices); err != nil {
		return nil, err
	}

	return devices, nil
}
