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
	SharedSecret string `json:"sharedSecret"`
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
		return nil
	}

	slog.Info("no existing keys found, registering new mobile client")
	return s.register()
}

// Keys returns the loaded client keys (nil if not initialized).
func (s *MobileClientService) Keys() *ClientKeys {
	return s.keys
}

// SharedSecret returns the raw shared secret bytes.
func (s *MobileClientService) SharedSecretBytes() []byte {
	return s.secret
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

	// Restore shared secret
	secret, err := base64.StdEncoding.DecodeString(keys.SharedSecret)
	if err != nil {
		return fmt.Errorf("decoding shared secret: %w", err)
	}

	s.keys = &keys
	s.rsaKey = rsaKey
	s.secret = secret
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

	// Generate a unique device ID for this client
	deviceUUID := generateUUID()

	// Register with ekey API
	registerReq := map[string]string{
		"DeviceId":   deviceUUID,
		"DeviceTyp":  "Physical",
		"DeviceName": "ekey-gateway",
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

	slog.Info("mobile client registered, response size", "bytes", len(body))
	slog.Debug("registration response", "body", string(body))

	// Parse response - we need to find the encrypted shared secret
	var registerResp map[string]any
	if err := json.Unmarshal(body, &registerResp); err != nil {
		// Response might not be JSON - log it for analysis
		slog.Warn("response is not JSON, raw response logged", "raw_b64", base64.StdEncoding.EncodeToString(body))
		return fmt.Errorf("parsing registration response: %w (raw: %s)", err, string(body))
	}

	slog.Info("registration response parsed", "keys", fmt.Sprintf("%v", keysOf(registerResp)))

	// Try to find the encrypted secret in the response
	// It could be in various fields - let's try common ones
	var encryptedSecret []byte
	for _, key := range []string{"encryptedSecret", "secret", "sharedSecret", "Secret", "EncryptedSecret", "key", "Key"} {
		if val, ok := registerResp[key]; ok {
			if str, ok := val.(string); ok {
				encryptedSecret, _ = base64.StdEncoding.DecodeString(str)
				if len(encryptedSecret) > 0 {
					slog.Info("found encrypted secret", "field", key, "size", len(encryptedSecret))
					break
				}
			}
		}
	}

	// If no known field, log the full response for manual analysis
	if len(encryptedSecret) == 0 {
		// Save the raw response for analysis
		slog.Warn("could not find encrypted secret in response, saving raw response for analysis")
		rawFile := s.cfg.ClientKeyFile + ".raw-response.json"
		os.WriteFile(rawFile, body, 0600)
		slog.Info("raw response saved", "file", rawFile)

		// Still save the keys (without shared secret) so we can analyze the response
		keys := &ClientKeys{
			DeviceID:   deviceUUID,
			PrivateKey: base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(rsaKey)),
			PublicKey:  pubB64,
			CreatedAt:  time.Now().Format(time.RFC3339),
		}
		s.keys = keys
		s.rsaKey = rsaKey
		s.saveKeys()
		return fmt.Errorf("registered but could not extract shared secret - check %s", rawFile)
	}

	// Decrypt the shared secret with our RSA private key
	secret, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKey, encryptedSecret, nil)
	if err != nil {
		// Try PKCS1v15 decryption as fallback
		secret, err = rsa.DecryptPKCS1v15(rand.Reader, rsaKey, encryptedSecret)
		if err != nil {
			return fmt.Errorf("decrypting shared secret failed (tried OAEP and PKCS1v15): %w", err)
		}
	}

	slog.Info("shared secret decrypted", "size", len(secret))

	// Compute keyHash (for identification in payloads)
	keyHashRaw := sha256.Sum256(secret)
	keyHash := base64.StdEncoding.EncodeToString(keyHashRaw[:])

	keys := &ClientKeys{
		DeviceID:     deviceUUID,
		PrivateKey:   base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(rsaKey)),
		PublicKey:    pubB64,
		SharedSecret: base64.StdEncoding.EncodeToString(secret),
		KeyHash:      keyHash,
		CreatedAt:    time.Now().Format(time.RFC3339),
	}

	s.keys = keys
	s.rsaKey = rsaKey
	s.secret = secret

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

func keysOf(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
