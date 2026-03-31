package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	ServerPort           int
	ClientID             string
	SystemID             string
	DeviceID             string
	TokenRefreshInterval int // seconds
	Email                string
	Password             string
	ClientKeyFile        string
	Scope                string
	RedirectURI          string
	TokenURL             string
	AuthorizeURL         string
	APIBase              string
	APIVersion           string
}

func Load() (Config, error) {
	email := os.Getenv("EKEY_EMAIL")
	if email == "" {
		return Config{}, fmt.Errorf("EKEY_EMAIL is required")
	}

	password := os.Getenv("EKEY_PASSWORD")
	if password == "" {
		return Config{}, fmt.Errorf("EKEY_PASSWORD is required")
	}

	return Config{
		ServerPort:           envInt("SERVER_PORT", 8080),
		ClientID:             env("EKEY_CLIENT_ID", "3312a901-79fb-469a-8d79-861787550778"),
		SystemID:             os.Getenv("EKEY_SYSTEM_ID"),
		DeviceID:             os.Getenv("EKEY_DEVICE_ID"),
		TokenRefreshInterval: envInt("TOKEN_REFRESH_INTERVAL", 60),
		Email:                email,
		Password:             password,
		ClientKeyFile:        env("EKEY_CLIENT_KEY_FILE", "ekey-client.json"),
		Scope:                "https://ekeybionyxprod.onmicrosoft.com/bionyx-web-prod/user_impersonation openid profile offline_access",
		RedirectURI:          "msal3312a901-79fb-469a-8d79-861787550778://auth",
		TokenURL:             "https://ekeybionyxprod.b2clogin.com/tfp/ekeybionyxprod.onmicrosoft.com/b2c_1_susi_v2/oauth2/v2.0/token",
		AuthorizeURL:         "https://ekeybionyxprod.b2clogin.com/tfp/ekeybionyxprod.onmicrosoft.com/b2c_1_susi_v2/oauth2/v2.0/authorize",
		APIBase:              "https://bionyx-prod.azurefd.net",
		APIVersion:           "6.5",
	}, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}
