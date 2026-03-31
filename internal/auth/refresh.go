package auth

import (
	"context"
	"log/slog"
	"time"
)

type Refresher struct {
	oauth         *OAuthClient
	state         *State
	checkInterval time.Duration
	refreshBefore time.Duration
}

func NewRefresher(oauth *OAuthClient, state *State, checkIntervalSec int) *Refresher {
	return &Refresher{
		oauth:         oauth,
		state:         state,
		checkInterval: time.Duration(checkIntervalSec) * time.Second,
		refreshBefore: 5 * time.Minute,
	}
}

func (r *Refresher) Run(ctx context.Context) {
	ticker := time.NewTicker(r.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("token refresher stopped")
			return
		case <-ticker.C:
			r.check()
		}
	}
}

func (r *Refresher) check() {
	status := r.state.Status()

	switch status {
	case TokenExpired:
		slog.Info("token expired, refreshing")
		r.doRefresh()
	case Authenticated:
		if r.state.ExpiresIn() < r.refreshBefore {
			slog.Info("token expires soon, refreshing", "expires_in", r.state.ExpiresIn().Round(time.Second))
			r.doRefresh()
		}
	}
}

func (r *Refresher) doRefresh() {
	resp, err := r.oauth.RefreshAccessToken()
	if err != nil {
		slog.Error("token refresh failed", "error", err)
		return
	}
	slog.Info("token refreshed", "expires_in", resp.ExpiresIn)
}
