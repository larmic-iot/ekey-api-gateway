package auth

import (
	"sync"
	"time"
)

type Status int

const (
	NotAuthenticated Status = iota
	Authenticated
	TokenExpired
)

func (s Status) String() string {
	switch s {
	case NotAuthenticated:
		return "not_authenticated"
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
	systemID     string
	deviceID     string
}

func NewState() *State {
	return &State{}
}

func (s *State) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.accessToken == "" {
		return NotAuthenticated
	}
	if time.Now().After(s.expiresAt) {
		if s.refreshToken != "" {
			return TokenExpired
		}
		return NotAuthenticated
	}
	return Authenticated
}

func (s *State) UpdateTokens(accessToken, refreshToken string, expiresIn int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessToken = accessToken
	s.refreshToken = refreshToken
	s.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
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
