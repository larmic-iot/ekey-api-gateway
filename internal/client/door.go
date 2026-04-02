package client

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/larmic-iot/ekey-api-gateway/internal/auth"
	"github.com/larmic-iot/ekey-api-gateway/internal/config"
)

var doorHTTPClient = &http.Client{Timeout: 10 * time.Second}

// DoorService handles door-opening commands.
type DoorService struct {
	cfg          config.Config
	state        *auth.State
	mobileClient *MobileClientService
}

func NewDoorService(cfg config.Config, state *auth.State, mc *MobileClientService) *DoorService {
	return &DoorService{cfg: cfg, state: state, mobileClient: mc}
}

// Ready returns true if the service can open the door.
func (s *DoorService) Ready() bool {
	return s.state.Status() == auth.Authenticated && s.mobileClient.Ready()
}

// ReadyReason returns a human-readable reason why the service is not ready.
func (s *DoorService) ReadyReason() string {
	if s.state.Status() != auth.Authenticated {
		return "not authenticated"
	}
	if s.mobileClient.Keys() == nil {
		return "mobile client not registered"
	}
	if !s.mobileClient.Ready() {
		return "shared secret not configured (set EKEY_SHARED_SECRET)"
	}
	return ""
}

// Open sends a door-open command to the device.
func (s *DoorService) Open() error {
	if !s.Ready() {
		return fmt.Errorf("door service not ready: %s", s.ReadyReason())
	}

	payload, err := s.buildPayload()
	if err != nil {
		return fmt.Errorf("building payload: %w", err)
	}

	return s.sendCommand(payload)
}

// buildPayload constructs the encrypted payload for directMessageToDevice.
// TODO: Complete after mitmproxy capture reveals the KDF and encryption details.
func (s *DoorService) buildPayload() (string, error) {
	// This is the skeleton — the crypto implementation requires
	// knowledge of the KDF algorithm and command format from mitmproxy analysis.
	return "", fmt.Errorf("payload encryption not yet implemented (waiting for mitmproxy capture)")
}

func (s *DoorService) sendCommand(payload string) error {
	body := map[string]any{
		"Method":  "queryMsg",
		"Channel": 100,
		"Payload": payload,
		"Timeout": 5000,
	}

	reqBody, _ := json.Marshal(body)
	url := fmt.Sprintf("%s/api/System/%s/Device/%s/directMessageToDevice?api-version=%s",
		s.cfg.APIBase, s.state.SystemID(), s.state.DeviceID(), s.cfg.APIVersion)

	req, err := http.NewRequest("POST", url, strings.NewReader(string(reqBody)))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+s.state.AccessToken())
	req.Header.Set("Accept", "application/json")

	slog.Debug("sending door open command", "url", url)

	resp, err := doorHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned %d: %s", resp.StatusCode, string(respBody))
	}

	slog.Info("door open command sent successfully", "response", string(respBody))
	return nil
}
