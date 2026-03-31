package auth

import (
	"sync"
	"time"
)

type Status int

const (
	NotAuthenticated Status = iota
	AwaitingCode
	Authenticated
	TokenExpired
)

func (s Status) String() string {
	switch s {
	case NotAuthenticated:
		return "not_authenticated"
	case AwaitingCode:
		return "awaiting_code"
	case Authenticated:
		return "authenticated"
	case TokenExpired:
		return "token_expired"
	default:
		return "unknown"
	}
}

type State struct {
	mu           sync.RWMutex
	accessToken  string
	refreshToken string
	expiresAt    time.Time
	codeVerifier string
	state        string
	systemID     string
	deviceID     string
}

func NewState() *State {
	return &State{}
}

func (s *State) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.accessToken == "" && s.codeVerifier == "" {
		return NotAuthenticated
	}
	if s.accessToken == "" && s.codeVerifier != "" {
		return AwaitingCode
	}
	if time.Now().After(s.expiresAt) {
		if s.refreshToken != "" {
			return TokenExpired
		}
		return NotAuthenticated
	}
	return Authenticated
}

func (s *State) SetAwaitingCode(codeVerifier, state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codeVerifier = codeVerifier
	s.state = state
}

func (s *State) UpdateTokens(accessToken, refreshToken string, expiresIn int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessToken = accessToken
	s.refreshToken = refreshToken
	s.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	s.codeVerifier = ""
	s.state = ""
}

func (s *State) AccessToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.accessToken
}

func (s *State) RefreshToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.refreshToken
}

func (s *State) CodeVerifier() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.codeVerifier
}

func (s *State) ExpectedState() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *State) ExpiresIn() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Until(s.expiresAt)
}

func (s *State) SetSystemID(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.systemID = id
}

func (s *State) SystemID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.systemID
}

func (s *State) SetDeviceID(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deviceID = id
}

func (s *State) DeviceID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.deviceID
}
