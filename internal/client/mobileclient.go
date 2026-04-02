package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/larmic-iot/ekey-api-gateway/internal/auth"
	"github.com/larmic-iot/ekey-api-gateway/internal/config"
)

var mobileHTTPClient = &http.Client{Timeout: 30 * time.Second}

// ClientKeys holds the persisted RSA key pair and shared secret from MobileClient registration.
type ClientKeys struct {
	DeviceID     string `json:"deviceId"`
	PrivateKey   string `json:"privateKey"`
	PublicKey    string `json:"publicKey"`
	SharedSecret string `json:"sharedSecret,omitempty"`
	KeyHash      string `json:"keyHash"`
	CreatedAt    string `json:"createdAt"`
}

// MobileClientService manages the MobileClient registration and key persistence.
type MobileClientService struct {
	cfg    config.Config
	state  *auth.State
	keys   *ClientKeys
	rsaKey *rsa.PrivateKey
	secret []byte
}

func NewMobileClientService(cfg config.Config, state *auth.State) *MobileClientService {
	return &MobileClientService{cfg: cfg, state: state}
}

// Init loads existing keys or registers a new MobileClient.
func (s *MobileClientService) Init() error {
	// Try loading existing keys
	if err := s.loadKeys(); err == nil {
		slog.Info("loaded existing mobile client keys", "deviceId", s.keys.DeviceID, "keyHash", s.keys.KeyHash)
		s.injectSharedSecretFromConfig()
		return nil
	}

	slog.Info("no existing keys found, registering new mobile client")
	if err := s.register(); err != nil {
		return err
	}

	s.injectSharedSecretFromConfig()
	return nil
}

// Ready returns true if keys and shared secret are available for door opening.
func (s *MobileClientService) Ready() bool {
	return s.keys != nil && len(s.secret) > 0
}

// Keys returns the loaded client keys (nil if not initialized).
func (s *MobileClientService) Keys() *ClientKeys {
	return s.keys
}

// RSAKey returns the RSA private key.
func (s *MobileClientService) RSAKey() *rsa.PrivateKey {
	return s.rsaKey
}

// SharedSecretBytes returns the raw shared secret bytes.
func (s *MobileClientService) SharedSecretBytes() []byte {
	return s.secret
}

// injectSharedSecretFromConfig sets the shared secret from the EKEY_SHARED_SECRET env var
// if it is configured and the keys don't already have one.
func (s *MobileClientService) injectSharedSecretFromConfig() {
	if len(s.secret) > 0 {
		slog.Info("shared secret already available", "size", len(s.secret))
		return
	}

	if s.cfg.SharedSecret == "" {
		slog.Warn("no shared secret available (door opening unavailable). Set EKEY_SHARED_SECRET to provide one.")
		return
	}

	secret, err := base64.StdEncoding.DecodeString(s.cfg.SharedSecret)
	if err != nil {
		slog.Error("failed to decode EKEY_SHARED_SECRET", "error", err)
		return
	}

	s.secret = secret
	s.keys.SharedSecret = s.cfg.SharedSecret
	slog.Info("shared secret injected from EKEY_SHARED_SECRET", "size", len(secret))

	if err := s.saveKeys(); err != nil {
		slog.Error("failed to persist injected shared secret", "error", err)
	}
}

func (s *MobileClientService) loadKeys() error {
	data, err := os.ReadFile(s.cfg.ClientKeyFile)
	if err != nil {
		return err
	}

	var keys ClientKeys
	if err := json.Unmarshal(data, &keys); err != nil {
		return fmt.Errorf("parsing key file: %w", err)
	}

	// Restore RSA private key
	privDER, err := base64.StdEncoding.DecodeString(keys.PrivateKey)
	if err != nil {
		return fmt.Errorf("decoding private key: %w", err)
	}
	rsaKey, err := x509.ParsePKCS1PrivateKey(privDER)
	if err != nil {
		return fmt.Errorf("parsing private key: %w", err)
	}

	s.keys = &keys
	s.rsaKey = rsaKey

	// Restore shared secret (optional — may not be available yet)
	if keys.SharedSecret != "" {
		secret, err := base64.StdEncoding.DecodeString(keys.SharedSecret)
		if err != nil {
			slog.Warn("failed to decode shared secret from key file", "error", err)
		} else {
			s.secret = secret
		}
	}

	return nil
}

func (s *MobileClientService) register() error {
	if s.state.Status() != auth.Authenticated {
		return fmt.Errorf("not authenticated, login first")
	}

	// Generate RSA-2048 key pair
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generating RSA key: %w", err)
	}

	// Encode public key as base64 (SubjectPublicKeyInfo / PKIX format)
	pubDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return fmt.Errorf("marshaling public key: %w", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pubDER)

	// Compute keyHash: SHA-256 of the public key DER bytes
	keyHashRaw := sha256.Sum256(pubDER)
	keyHash := base64.StdEncoding.EncodeToString(keyHashRaw[:])

	// Generate a unique device ID for this client
	deviceUUID := generateUUID()

	// Register with ekey API
	registerReq := map[string]string{
		"DeviceId":   deviceUUID,
		"DeviceTyp":  "Physical",
		"DeviceName": "iPhone",
		"PublicKey":  pubB64,
		"Created":    time.Now().Format("2006-01-02T15:04:05.000000-07:00"),
	}

	reqBody, _ := json.Marshal(registerReq)
	url := fmt.Sprintf("%s/api/System/%s/MobileClient/create?api-version=%s",
		s.cfg.APIBase, s.state.SystemID(), s.cfg.APIVersion)

	req, _ := http.NewRequest("POST", url, strings.NewReader(string(reqBody)))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+s.state.AccessToken())
	req.Header.Set("Accept", "application/json")

	slog.Debug("registering mobile client", "deviceId", deviceUUID, "url", url)

	resp, err := mobileHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("registration request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registration returned %d: %s", resp.StatusCode, string(body))
	}

	slog.Info("mobile client registered", "response", string(body))

	// Save keys (shared secret will be injected later via EKEY_SHARED_SECRET or mitmproxy)
	keys := &ClientKeys{
		DeviceID:   deviceUUID,
		PrivateKey: base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(rsaKey)),
		PublicKey:  pubB64,
		KeyHash:    keyHash,
		CreatedAt:  time.Now().Format(time.RFC3339),
	}

	s.keys = keys
	s.rsaKey = rsaKey

	return s.saveKeys()
}

func (s *MobileClientService) saveKeys() error {
	data, _ := json.MarshalIndent(s.keys, "", "  ")
	if err := os.WriteFile(s.cfg.ClientKeyFile, data, 0600); err != nil {
		return fmt.Errorf("saving key file: %w", err)
	}
	slog.Info("client keys saved", "file", s.cfg.ClientKeyFile)
	return nil
}

func generateUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%08X-%04X-%04X-%04X-%012X",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
