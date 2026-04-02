package client

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

type DiscoveryService struct {
	cfg   config.Config
	state *auth.State
}

func NewDiscoveryService(cfg config.Config, state *auth.State) *DiscoveryService {
	return &DiscoveryService{cfg: cfg, state: state}
}

// Discover fetches systemID and deviceID from the ekey API and stores them in state.
// If config overrides are set (via env vars), those take precedence.
func (d *DiscoveryService) Discover() error {
	if d.state.Status() != auth.Authenticated {
		return fmt.Errorf("not authenticated, login first")
	}

	// Discover systemID
	systemID := d.cfg.SystemID
	if systemID == "" {
		var err error
		systemID, err = d.fetchSystemID()
		if err != nil {
			return fmt.Errorf("discovering systemID: %w", err)
		}
	} else {
		slog.Info("using systemID from config override", "systemId", systemID)
	}
	d.state.SetSystemID(systemID)

	// Discover deviceID
	deviceID := d.cfg.DeviceID
	if deviceID == "" {
		var err error
		deviceID, err = d.fetchDeviceID(systemID)
		if err != nil {
			return fmt.Errorf("discovering deviceID: %w", err)
		}
	} else {
		slog.Info("using deviceID from config override", "deviceId", deviceID)
	}
	d.state.SetDeviceID(deviceID)

	// Discover functionID
	functionID := d.cfg.FunctionID
	if functionID == "" {
		var err error
		functionID, err = d.fetchFunctionID(systemID)
		if err != nil {
			slog.Warn("discovering functionID failed (door opening may be unavailable)", "error", err)
		}
	} else {
		slog.Info("using functionID from config override", "functionId", functionID)
	}
	if functionID != "" {
		d.state.SetFunctionID(functionID)
	}

	return nil
}

func (d *DiscoveryService) fetchSystemID() (string, error) {
	url := fmt.Sprintf("%s/api/User/UserAndSystems?api-version=%s", d.cfg.APIBase, d.cfg.APIVersion)

	body, err := d.apiGet(url)
	if err != nil {
		return "", err
	}

	var resp struct {
		UserSystems []struct {
			SystemID string `json:"systemId"`
		} `json:"userSystems"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("parsing UserAndSystems response: %w", err)
	}

	if len(resp.UserSystems) == 0 {
		return "", fmt.Errorf("no systems found for user")
	}

	systemID := resp.UserSystems[0].SystemID
	slog.Info("discovered systemID", "systemId", systemID)
	return systemID, nil
}

func (d *DiscoveryService) fetchDeviceID(systemID string) (string, error) {
	url := fmt.Sprintf("%s/api/System/%s/Device/overview?api-version=%s", d.cfg.APIBase, systemID, d.cfg.APIVersion)

	body, err := d.apiGet(url)
	if err != nil {
		return "", err
	}

	var devices []struct {
		DeviceID string `json:"deviceId"`
	}
	if err := json.Unmarshal(body, &devices); err != nil {
		return "", fmt.Errorf("parsing Device/overview response: %w", err)
	}

	if len(devices) == 0 {
		return "", fmt.Errorf("no devices found in system %s", systemID)
	}

	deviceID := devices[0].DeviceID
	slog.Info("discovered deviceID", "deviceId", deviceID)
	return deviceID, nil
}

func (d *DiscoveryService) fetchFunctionID(systemID string) (string, error) {
	url := fmt.Sprintf("%s/api/System/%s/Function/overview?api-version=%s", d.cfg.APIBase, systemID, d.cfg.APIVersion)

	body, err := d.apiGet(url)
	if err != nil {
		return "", err
	}

	var functions []struct {
		ID int `json:"id"`
	}
	if err := json.Unmarshal(body, &functions); err != nil {
		return "", fmt.Errorf("parsing Function/overview response: %w", err)
	}

	if len(functions) == 0 {
		return "", fmt.Errorf("no functions found in system %s", systemID)
	}

	functionID := fmt.Sprintf("%d", functions[0].ID)
	slog.Info("discovered functionID", "functionId", functionID)
	return functionID, nil
}

var discoveryClient = &http.Client{Timeout: 30 * time.Second}

func (d *DiscoveryService) apiGet(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+d.state.AccessToken())
	req.Header.Set("Accept", "application/json")

	resp, err := discoveryClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}
