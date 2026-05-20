# stagepass-auth-service

**Tier:** T1 — Critical (99.9% SLO)
**Framework:** Spring Boot 3.5.0 + Spring Security 6.5 + Java 21
**Databases:** PostgreSQL 16 (auth_db) · Redis 7 (DB 0)
**Phase:** 3

---

## What This Service Does

Handles the complete authentication lifecycle for the StagePass platform:

- **User registration** with four roles: CUSTOMER, ORGANISER, VENUE, ADMIN
- **Login** with RS256 JWT issuance and opaque refresh token
- **Token refresh** with rotation (each refresh token is single-use)
- **Logout** — revokes the current JTI and all refresh tokens
- **JWKS endpoint** — distributes the RSA public key so downstream services validate JWTs locally (no per-request Auth call)
- **Password management** — change password, password reset flow
- **Admin user management** — list users, suspend, reinstate, revoke sessions
- **Account lockout** — after N failed login attempts, locks account for M minutes

### What It Does NOT Do

- Authorization decisions beyond role extraction — each service enforces its own RBAC
- Session storage — JWTs are stateless; only the JTI blocklist (Redis) is stateful
- Email sending — password reset token is logged in Phase 3; replaced in Phase 6

---

## Dependencies

| Direction | Service | Protocol | Why |
|-----------|---------|----------|-----|
| **Uses** | PostgreSQL | JDBC | User accounts, tokens, audit log |
| **Uses** | Redis | Lettuce | JTI blocklist (DB 0), login rate limiting |
| **Called by** | API Gateway | REST | All authenticated requests forward JWT here for JWKS |
| **Called by** | All services | JWKS | Services fetch public key on startup |

---

## Local Setup (< 30 minutes from clone)

### Prerequisites

- Docker Desktop or Docker Engine ≥ 24
- OpenSSL (generate RSA key pair)
- Java 21 (for running tests without Docker)

### Step 1 — Generate RSA key pair

The service requires an RSA key pair. **Never commit keys.** Generate a local dev pair:

```bash
# Generate RSA 2048-bit private key
openssl genrsa -out /tmp/auth-private.pem 2048

# Export PKCS8 DER-encoded private key — base64, no line breaks (-w 0)
openssl pkcs8 -topk8 -inform PEM -outform DER -in /tmp/auth-private.pem -nocrypt \
  | base64 -w 0 > /tmp/auth-private.b64

# Export X.509 DER-encoded public key — base64, no line breaks (-w 0)
openssl rsa -in /tmp/auth-private.pem -pubout -outform DER \
  | base64 -w 0 > /tmp/auth-public.b64

# Write to .env file (gitignored — never commit this file)
echo "AUTH_RSA_PRIVATE_KEY=$(cat /tmp/auth-private.b64)" > .env
echo "AUTH_RSA_PUBLIC_KEY=$(cat /tmp/auth-public.b64)" >> .env
```

### Step 2 — Start the service

```bash
docker compose up --build
```

This starts PostgreSQL, Redis, and the Auth Service.
Flyway migrations run automatically on startup.

### Step 3 — Verify it's running

```bash
# Liveness
curl http://localhost:8081/health/live

# Readiness (checks PostgreSQL + Redis + RSA key)
curl http://localhost:8081/health/ready

# JWKS (RSA public key)
curl http://localhost:8081/auth/jwks | jq .
```

### Step 4 — Register a user

```bash
curl -X POST http://localhost:8081/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "Password1!",
    "role": "CUSTOMER",
    "displayName": "Alice"
  }'
```

Expected response:
```json
{
  "accessToken": "eyJ...",
  "refreshToken": "...",
  "expiresIn": 900,
  "tokenType": "Bearer"
}
```

---

## Running Tests

```bash
# Unit tests only (fast — no Docker required)
mvn test -Dtest="**/unit/**" -DskipITs=true

# Integration tests (requires Docker — Testcontainers spins up Postgres + Redis)
AUTH_RSA_PRIVATE_KEY=$(cat /tmp/auth-private.b64) \
AUTH_RSA_PUBLIC_KEY=$(cat /tmp/auth-public.b64) \
APP_JWT_KEY_ID=local-test-key \
mvn verify -Dsurefire.skip=true -Djacoco.skip=true

# All tests with coverage report
AUTH_RSA_PRIVATE_KEY=$(cat /tmp/auth-private.b64) \
AUTH_RSA_PUBLIC_KEY=$(cat /tmp/auth-public.b64) \
APP_JWT_KEY_ID=local-test-key \
mvn verify
open target/site/jacoco/index.html
```

---

## Environment Variables

All secrets come from Vault in production (NFR-SEC-008). For local dev, set as environment variables.

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `SPRING_DATASOURCE_URL` | Yes | PostgreSQL JDBC URL | `jdbc:postgresql://localhost:5433/auth_db` |
| `SPRING_DATASOURCE_USERNAME` | Yes | PostgreSQL user | `auth_user` |
| `SPRING_DATASOURCE_PASSWORD` | Yes | PostgreSQL password | (Vault) |
| `SPRING_DATA_REDIS_HOST` | Yes | Redis host | `localhost` |
| `SPRING_DATA_REDIS_PORT` | Yes | Redis port | `6380` |
| `SPRING_DATA_REDIS_DATABASE` | No | Redis DB index | `0` |
| `AUTH_RSA_PRIVATE_KEY` | Yes | PKCS8 RSA private key, base64 DER, no line breaks | (Vault) |
| `AUTH_RSA_PUBLIC_KEY` | Yes | X.509 RSA public key, base64 DER, no line breaks | (Vault) |
| `APP_JWT_KEY_ID` | No | Key ID for JWKS kid field | `stagepass-auth-key-1` |
| `APP_JWT_ACCESS_TOKEN_TTL_SECONDS` | No | Access token lifetime | `900` |
| `APP_JWT_REFRESH_TOKEN_TTL_SECONDS` | No | Refresh token lifetime | `604800` |
| `APP_RATE_LIMIT_LOGIN_MAX_PER_MINUTE` | No | Login rate limit per IP | `5` |
| `APP_LOCKOUT_MAX_ATTEMPTS` | No | Failed attempts before lockout | `10` |
| `APP_LOCKOUT_DURATION_MINUTES` | No | Lockout duration | `30` |

---

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/register` | None (ADMIN role requires Admin JWT) | Register a new user |
| POST | `/auth/login` | None | Authenticate, get token pair |
| POST | `/auth/refresh` | None | Rotate refresh token |
| POST | `/auth/logout` | JWT | Revoke current session |
| GET | `/auth/me` | JWT | Get own profile |
| PUT | `/auth/me` | JWT | Update own display name |
| POST | `/auth/password/change` | JWT | Change password |
| POST | `/auth/password/reset/request` | None | Request password reset (STUB in Phase 3) |
| POST | `/auth/password/reset/confirm` | None | Complete password reset |
| GET | `/auth/users` | ADMIN JWT | List all users |
| GET | `/auth/users/{userId}` | ADMIN JWT | Get user by ID |
| POST | `/auth/users/{userId}/suspend` | ADMIN JWT | Suspend user account |
| POST | `/auth/users/{userId}/reinstate` | ADMIN JWT | Reinstate user account |
| POST | `/auth/users/{userId}/revoke-sessions` | ADMIN JWT | Force logout user |
| GET | `/auth/jwks` | None | RSA public key (JWKS format) |
| GET | `/health/live` | None | Liveness probe |
| GET | `/health/ready` | None | Readiness probe |

Full OpenAPI spec: [`stagepass-docs/docs/api/auth.yaml`](https://github.com/stagepass-aiman/stagepass-docs/blob/main/docs/api/auth.yaml)

---

## Architecture Notes

- **Why RS256 (not HS256)?** RS256 allows downstream services to verify JWTs using only the public key (from JWKS). With HS256, every service needs the shared secret — a security anti-pattern at scale. See ADR-003.
- **Why a JTI blocklist in Redis?** JWTs are stateless — you cannot invalidate them without checking a revocation list. The blocklist stores only the JTI (not the full token) with a TTL equal to the remaining token lifetime. This bounds Redis storage. See ADR-003.
- **Why BIGSERIAL for admin_audit_log PK?** Monotonic integer ordering gives unambiguous forensic sequencing and gap detection (a missing ID reveals a deleted row). UUID ordering is lexicographic, not temporal. See ER diagram.

---

## CHANGELOG

See [CHANGELOG.md](./CHANGELOG.md).
