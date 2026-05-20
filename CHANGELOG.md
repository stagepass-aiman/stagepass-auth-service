# Changelog — stagepass-auth-service

All notable changes to this service are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [0.1.0] — Phase 3 Scaffold

### Added
- Full user registration, login, logout, token refresh flow
- RS256 JWT issuance with JWKS public key distribution endpoint
- Redis JTI blocklist for token revocation (logout + password change)
- Four-role RBAC model: CUSTOMER, ORGANISER, VENUE, ADMIN
- Account lockout after configurable failed login attempts (THR-AUTH-02)
- Timing attack prevention — bcrypt always runs on login (THR-AUTH-07)
- Refresh token rotation — each use issues a new token and revokes the old (THR-AUTH-03)
- Password reset flow (token STUB — email integration deferred to Phase 6)
- Admin user management: list, suspend, reinstate
- PostgreSQL schema with Flyway migrations (4 migrations):
  - V1: users table with role/status enums and updated_at trigger
  - V2: refresh_tokens with SHA-256 hash storage
  - V3: password_reset_tokens (single-use)
  - V4: admin_audit_log with BIGSERIAL PK and append-only REVOKE
- RFC 9457 Problem Details error responses on all endpoints
- Liveness and readiness health check endpoints (/health/live, /health/ready)
- Structured JSON logging with traceId/spanId MDC fields (NFR-OBS-001)
- Virtual threads enabled (NFR-PERF-042)
- Unit tests: AuthServiceTest, JwtServiceTest
- Integration tests: AuthControllerIT (Testcontainers PostgreSQL + Redis)
- Multi-stage Dockerfile (builder: maven:3.9-eclipse-temurin-21-alpine, runtime: distroless/java21)
- CI pipeline: secrets-scan → unit-test → integration-test → SAST → SCA → build-and-scan
- JaCoCo coverage gate: ≥80% branch coverage enforced in CI (NFR-MAINT-001)

### Security
- bcrypt cost ≥ 12 (NFR-SEC-007)
- Access token TTL: 900s / Refresh token TTL: 604800s (NFR-SEC-002)
- RBAC enforced at service layer and controller layer (NFR-SEC-003)
- Admin audit log append-only — DELETE/UPDATE/TRUNCATE revoked at DB level (THR-AUTH-11)

### Known Limitations (deferred)
- Email sending for password reset is a STUB — logs token to INFO. Replaced in Phase 6.
- No Pact consumer contract yet — added in Phase 7 when API Gateway is the consumer.
- mTLS not configured — deferred to Phase 9 (Istio).
- Vault integration for RSA key loading is mocked via env vars — replaced in Phase 2.
