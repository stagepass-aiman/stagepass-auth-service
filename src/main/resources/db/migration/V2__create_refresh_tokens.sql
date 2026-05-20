-- ============================================================
-- V2__create_refresh_tokens.sql
-- ============================================================
--
-- Stores refresh tokens in hashed form. The raw token is NEVER
-- persisted — only SHA-256(token) is stored.
--
-- Design decisions:
--
-- 1. token_hash = SHA-256(raw_token), stored as hex string (64 chars).
--    A DB dump does not expose usable tokens.
--    Lookup: compute SHA-256 of the presented token, match against hash.
--
-- 2. revoked_at is NULLABLE, not a boolean is_revoked.
--    NULL = active. Non-null = revoked at that timestamp.
--    WHY: revoked_at is both the revocation flag AND the revocation
--    timestamp in one column. A boolean + separate revoked_at column
--    would allow inconsistency (true with NULL timestamp, etc.).
--
-- 3. ON DELETE CASCADE from users:
--    When a user is deleted, all their tokens are deleted atomically
--    in the same transaction. No orphaned tokens possible.
--
-- 4. issued_from_ip and user_agent support anomaly detection per
--    THR-AUTH-03 ("log each refresh token use with IP and user-agent").
-- ============================================================

CREATE TABLE refresh_tokens (
    id              UUID            NOT NULL DEFAULT gen_random_uuid(),

    -- FK to the owning user. Cascade ensures no orphaned tokens.
    user_id         UUID            NOT NULL,

    -- SHA-256 hash of the raw opaque token presented by the client.
    -- Stored as lowercase hex (64 characters).
    token_hash      VARCHAR(64)     NOT NULL,

    -- Token is invalid after this timestamp.
    expires_at      TIMESTAMPTZ     NOT NULL,

    -- NULL = token is active.
    -- Non-null = token was revoked at this time (rotation or logout).
    -- On rotation: the old token's revoked_at is set before the new
    -- token is inserted — these two writes are in the same transaction.
    revoked_at      TIMESTAMPTZ     NULL,

    -- Source IP at token issuance. Used for anomaly detection.
    -- INET type supports both IPv4 and IPv6.
    issued_from_ip  VARCHAR(45)     NULL,

    -- Browser/client identifier at issuance. Used for anomaly detection.
    user_agent      VARCHAR(512)    NULL,

    -- Issuance timestamp.
    issued_at       TIMESTAMPTZ     NOT NULL DEFAULT now(),

    CONSTRAINT pk_refresh_tokens PRIMARY KEY (id),
    CONSTRAINT uq_refresh_tokens_hash UNIQUE (token_hash),
    CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id)
        REFERENCES users (id)
        ON DELETE CASCADE
        DEFERRABLE INITIALLY DEFERRED
);

-- ────────────────────────────────────────────────────────────
-- Indexes
-- ────────────────────────────────────────────────────────────

-- Primary lookup path: verify a presented refresh token by its hash.
-- The UNIQUE constraint already creates a B-tree index on token_hash.

-- Find all active tokens for a user (used during suspend / revoke-all-sessions).
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);

-- Periodic cleanup job: find expired tokens for pruning.
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens (expires_at);

COMMENT ON TABLE refresh_tokens IS
    'Hashed refresh tokens. Raw token is never persisted. Rotation-on-use enforced in AuthService. (NFR-SEC-002)';
COMMENT ON COLUMN refresh_tokens.token_hash IS
    'SHA-256(raw_token) as lowercase hex. Never the raw token itself.';
COMMENT ON COLUMN refresh_tokens.revoked_at IS
    'NULL = active. Set atomically with new token insert on rotation. (THR-AUTH-03)';
