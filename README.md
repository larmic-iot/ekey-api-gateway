# ekey API Gateway

An API gateway for the [ekey bionyx](https://www.ekey.net/) smart lock system that enables programmatic door control via a REST API.

## Background

The ekey bionyx system provides a mobile app for managing fingerprint-based door locks, but does not offer a public API for programmatic door control. This gateway bridges that gap by handling the OAuth2 authentication flow against Azure AD B2C, managing the token lifecycle (including automatic refresh), and proxying authenticated requests to the ekey bionyx backend API.

## Features

- **Automated OAuth2 Login** - Programmatic login using email/password via Azure AD B2C with PKCE
- **Token Management** - Automatic token refresh before expiration
- **API Proxy** - Transparent proxy to the ekey bionyx API with automatic Bearer token injection
- **MobileClient Registration** - RSA-2048 key pair generation and device registration
- **Health Endpoints** - Liveness, readiness, and general health checks
- **Graceful Shutdown** - Clean shutdown on SIGINT/SIGTERM
- **Docker Support** - Multi-stage Docker build for minimal container images

## Prerequisites

- Go 1.26+ or Docker
- An ekey bionyx account with a registered smart lock system

## Configuration

The gateway is configured via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_PORT` | `8080` | HTTP server port |
| `EKEY_EMAIL` | | ekey account email (enables auto-login) |
| `EKEY_PASSWORD` | | ekey account password (enables auto-login) |
| `EKEY_SYSTEM_ID` | *(built-in)* | Your ekey system ID |
| `EKEY_DEVICE_ID` | *(built-in)* | Target device ID |
| `EKEY_CLIENT_ID` | *(built-in)* | OAuth2 client ID |
| `TOKEN_REFRESH_INTERVAL` | `60` | Token refresh check interval in seconds |
| `EKEY_CLIENT_KEY_FILE` | `ekey-client.json` | Path to persisted client keys |

## Quick Start

### Run locally

```bash
export EKEY_EMAIL="your@email.com"
export EKEY_PASSWORD="your-password"
make run
```

### Run with Docker

```bash
make docker-build
docker run --rm -p 8080:8080 \
  -e EKEY_EMAIL="your@email.com" \
  -e EKEY_PASSWORD="your-password" \
  ekey-api-gateway
```

## API Endpoints

### Health

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | General health status |
| GET | `/health/ready` | Readiness probe (authenticated?) |
| GET | `/health/live` | Liveness probe |

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| POST | `/oauth/login` | Login with email and password |
| POST | `/oauth/callback` | Manual OAuth callback (fallback for browser-based flow) |
| POST | `/oauth/refresh` | Force token refresh |

### Proxy

| Method | Path | Description |
|--------|------|-------------|
| ANY | `/proxy/*` | Proxy to ekey bionyx API |

The proxy strips the `/proxy` prefix and forwards the request to the ekey API with the current Bearer token. The `api-version` query parameter is added automatically if not present.

**Example:** `GET /proxy/api/User/UserAndSystems` proxies to `https://bionyx-prod.azurefd.net/api/User/UserAndSystems?api-version=6.5`

## Project Status

The gateway currently supports authentication, token management, and API proxying. Direct door unlocking via the `directMessageToDevice` endpoint requires a shared secret for AES-256-GCM payload encryption. See [NEXT_STEPS.md](NEXT_STEPS.md) for details on the current progress and next steps.

## Documentation

- [API.md](API.md) - ekey bionyx REST API reference
- [EKEY_BIONYX_API.md](EKEY_BIONYX_API.md) - Detailed reverse-engineering notes
- [NEXT_STEPS.md](NEXT_STEPS.md) - Current status and next implementation steps

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
