package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/larmic-iot/ekey-api-gateway/internal/auth"
	"github.com/larmic-iot/ekey-api-gateway/internal/config"
)

type InfoHandler struct {
	state  *auth.State
	cfg    config.Config
	client *http.Client

	mu    sync.RWMutex
	cache *infoCache
}

type infoCache struct {
	User    infoUser     `json:"user"`
	Systems []infoSystem `json:"systems"`
}

type infoUser struct {
	UserID      string `json:"userId"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
}

type infoSystem struct {
	SystemID  string       `json:"systemId"`
	Created   string       `json:"created"`
	Onboarded bool         `json:"onboarded"`
	Devices   []infoDevice `json:"devices"`
}

type infoDevice struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func NewInfoHandler(state *auth.State, cfg config.Config) *InfoHandler {
	return &InfoHandler{
		state:  state,
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// Load fetches user, system and device info from the ekey API and caches it.
func (h *InfoHandler) Load() error {
	data, err := h.fetchInfo()
	if err != nil {
		return err
	}

	h.mu.Lock()
	h.cache = data
	h.mu.Unlock()

	slog.Info("info cache updated", "systems", len(data.Systems))
	return nil
}

// RunRefresh periodically refreshes the cached info.
func (h *InfoHandler) RunRefresh(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("info refresher stopped")
			return
		case <-ticker.C:
			if h.state.Status() != auth.Authenticated {
				continue
			}
			if err := h.Load(); err != nil {
				slog.Error("info refresh failed", "error", err)
			}
		}
	}
}

func (h *InfoHandler) Info(w http.ResponseWriter, _ *http.Request) {
	if h.state.Status() != auth.Authenticated {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "not authenticated"})
		return
	}

	h.mu.RLock()
	cached := h.cache
	h.mu.RUnlock()

	if cached == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "info not yet loaded"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"auth": map[string]any{
			"status":    h.state.Status().String(),
			"expiresIn": int(h.state.ExpiresIn().Seconds()),
		},
		"user":    cached.User,
		"systems": cached.Systems,
	})
}

func (h *InfoHandler) fetchInfo() (*infoCache, error) {
	userAndSystems, err := h.fetchUserAndSystems()
	if err != nil {
		return nil, fmt.Errorf("fetching user and systems: %w", err)
	}

	systems := make([]infoSystem, 0, len(userAndSystems.UserSystems))
	for _, sys := range userAndSystems.UserSystems {
		devices, err := h.fetchDevices(sys.SystemID)
		if err != nil {
			slog.Error("fetching devices failed", "systemId", sys.SystemID, "error", err)
		}

		systems = append(systems, infoSystem{
			SystemID:  sys.SystemID,
			Created:   sys.Created,
			Onboarded: sys.Onboarded,
			Devices:   devices,
		})
	}

	return &infoCache{
		User: infoUser{
			UserID:      userAndSystems.User.UserID,
			DisplayName: userAndSystems.User.DisplayName,
			Email:       userAndSystems.User.Email,
		},
		Systems: systems,
	}, nil
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

func (h *InfoHandler) fetchDevices(systemID string) ([]infoDevice, error) {
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

	var devices []infoDevice
	if err := json.Unmarshal(body, &devices); err != nil {
		return nil, err
	}

	return devices, nil
}
