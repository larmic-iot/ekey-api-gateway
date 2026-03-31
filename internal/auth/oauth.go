package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/larmic-iot/ekey-api-gateway/internal/config"
	"github.com/larmic-iot/ekey-api-gateway/internal/crypto"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token,omitempty"`
}

type OAuthClient struct {
	cfg   config.Config
	state *State
}

func NewOAuthClient(cfg config.Config, state *State) *OAuthClient {
	return &OAuthClient{cfg: cfg, state: state}
}

// LoginWithCredentials performs the full Azure AD B2C login flow programmatically.
// 1. GET /authorize → extract CSRF token, cookies, tx/p params
// 2. POST /SelfAsserted → submit credentials
// 3. GET /confirmed → get redirect with auth code
// 4. POST /token → exchange code for tokens
func (c *OAuthClient) LoginWithCredentials(email, password string) (*TokenResponse, error) {
	verifier, err := crypto.GenerateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("generating code verifier: %w", err)
	}

	stateParam, err := crypto.GenerateState()
	if err != nil {
		return nil, fmt.Errorf("generating state: %w", err)
	}

	challenge := crypto.GenerateCodeChallenge(verifier)

	// Cookie jar to maintain session across requests
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Follow redirects but stop if we hit the msal:// scheme
			if strings.HasPrefix(req.URL.String(), "msal") {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// Step 1: GET /authorize → get HTML page with CSRF token and session cookies
	authorizeParams := url.Values{
		"client_id":             {c.cfg.ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {c.cfg.RedirectURI},
		"scope":                 {c.cfg.Scope},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {stateParam},
		"client_info":           {"1"},
	}
	authorizeURL := c.cfg.AuthorizeURL + "?" + authorizeParams.Encode()

	slog.Debug("step 1: fetching authorize page")
	resp, err := client.Get(authorizeURL)
	if err != nil {
		return nil, fmt.Errorf("authorize request failed: %w", err)
	}
	defer resp.Body.Close()
	authorizeBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authorize returned %d", resp.StatusCode)
	}

	// Extract CSRF token from cookie
	csrfToken := ""
	authorizeParsedURL, _ := url.Parse(authorizeURL)
	for _, cookie := range jar.Cookies(authorizeParsedURL) {
		if cookie.Name == "x-ms-cpim-csrf" {
			csrfToken = cookie.Value
			break
		}
	}
	if csrfToken == "" {
		return nil, fmt.Errorf("CSRF token not found in cookies")
	}

	// Extract StateProperties (tx) and policy (p) from the page for SelfAsserted URL
	txParam := extractParam(string(authorizeBody), `"transId":"([^"]+)"`)
	if txParam == "" {
		txParam = extractParam(string(authorizeBody), `StateProperties=([^&"]+)`)
	}
	if txParam == "" {
		return nil, fmt.Errorf("could not extract transaction ID from authorize page")
	}

	// Step 2: POST /SelfAsserted → submit credentials
	selfAssertedPath := fmt.Sprintf("/ekeybionyxprod.onmicrosoft.com/B2C_1_susi_v2/SelfAsserted?tx=StateProperties=%s&p=B2C_1_susi_v2", txParam)
	selfAssertedURL := "https://ekeybionyxprod.b2clogin.com" + selfAssertedPath

	formData := url.Values{
		"request_type": {"RESPONSE"},
		"email":        {email},
		"password":     {password},
	}

	req, _ := http.NewRequest("POST", selfAssertedURL, strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("X-CSRF-TOKEN", csrfToken)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("Origin", "https://ekeybionyxprod.b2clogin.com")
	req.Header.Set("Referer", authorizeURL)

	slog.Debug("step 2: submitting credentials")
	resp, err = client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("SelfAsserted request failed: %w", err)
	}
	defer resp.Body.Close()
	selfAssertedBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SelfAsserted returned %d: %s", resp.StatusCode, string(selfAssertedBody))
	}

	// Check for login error in response
	if strings.Contains(string(selfAssertedBody), "\"status\":\"FAIL\"") {
		return nil, fmt.Errorf("login failed: invalid credentials")
	}

	// Step 3: GET /confirmed → triggers redirect to msal:// with auth code
	// Extract CSRF token again (may have been updated)
	for _, cookie := range jar.Cookies(authorizeParsedURL) {
		if cookie.Name == "x-ms-cpim-csrf" {
			csrfToken = cookie.Value
			break
		}
	}

	confirmedPath := fmt.Sprintf("/ekeybionyxprod.onmicrosoft.com/B2C_1_susi_v2/api/CombinedSigninAndSignup/confirmed?rememberMe=false&csrf_token=%s&tx=StateProperties=%s&p=B2C_1_susi_v2",
		url.QueryEscape(csrfToken), txParam)
	confirmedURL := "https://ekeybionyxprod.b2clogin.com" + confirmedPath

	req, _ = http.NewRequest("GET", confirmedURL, nil)
	req.Header.Set("Referer", authorizeURL)

	slog.Debug("step 3: fetching confirmed (redirect with auth code)")
	resp, err = client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("confirmed request failed: %w", err)
	}
	defer resp.Body.Close()

	// The response should be a 302 redirect to msal://...?code=XXX
	// Our CheckRedirect stops at msal:// scheme, so we get the Location header
	var authCode string
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		location := resp.Header.Get("Location")
		authCode = extractCodeFromRedirectURL(location)
	}

	// If not a redirect, the confirmed endpoint itself may return a page that redirects
	if authCode == "" {
		confirmedBody, _ := io.ReadAll(resp.Body)
		authCode = extractCodeFromRedirectURL(string(confirmedBody))
	}

	if authCode == "" {
		return nil, fmt.Errorf("could not extract auth code from confirmed response (status: %d)", resp.StatusCode)
	}

	slog.Debug("step 4: exchanging auth code for tokens")

	// Step 4: Exchange auth code for tokens
	return c.exchangeCodeWithVerifier(authCode, verifier)
}

func (c *OAuthClient) exchangeCodeWithVerifier(code, verifier string) (*TokenResponse, error) {
	data := url.Values{
		"client_id":     {c.cfg.ClientID},
		"scope":         {c.cfg.Scope},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.cfg.RedirectURI},
		"code_verifier": {verifier},
	}
	return c.tokenRequest(data)
}

func (c *OAuthClient) RefreshAccessToken() (*TokenResponse, error) {
	refreshToken := c.state.RefreshToken()
	if refreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}

	data := url.Values{
		"client_id":     {c.cfg.ClientID},
		"scope":         {c.cfg.Scope},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"redirect_uri":  {c.cfg.RedirectURI},
	}

	return c.tokenRequest(data)
}

var tokenClient = &http.Client{Timeout: 30 * time.Second}

func (c *OAuthClient) tokenRequest(data url.Values) (*TokenResponse, error) {
	resp, err := tokenClient.Post(c.cfg.TokenURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}

	c.state.UpdateTokens(tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.ExpiresIn)
	return &tokenResp, nil
}

var (
	codeRegex    = regexp.MustCompile(`[?&]code=([^&]+)`)
	transIDRegex = regexp.MustCompile(`"transId"\s*:\s*"([^"]+)"`)
	stateRegex   = regexp.MustCompile(`StateProperties=([^&"'\s]+)`)
)

func extractCodeFromRedirectURL(s string) string {
	matches := codeRegex.FindStringSubmatch(s)
	if len(matches) > 1 {
		code, _ := url.QueryUnescape(matches[1])
		return code
	}
	return ""
}

func extractParam(body, pattern string) string {
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
