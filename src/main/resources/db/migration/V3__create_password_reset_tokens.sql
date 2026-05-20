-- ============================================================
-- V3__create_password_reset_tokens.sql
-- ============================================================
--
-- Time-limited, single-use tokens for the forgot-password flow.
--
-- Design: same hash pattern as refresh_tokens.
-- Raw token goes in the email link; only the hash is stored.
-- used_at being non-null means the token has been consumed.
-- ============================================================

CREATE TABLE password_reset_tokens (
    id          UUID        NOT NULL DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL,

    -- SHA-256(raw_token) as lowercase hex.
    -- The raw token is embedded in the password reset email link.
    token_hash  VARCHAR(64) NOT NULL,

    -- Tokens are valid for 1 hour from creation.
    expires_at  TIMESTAMPTZ NOT NULL,

    -- Single-use enforcement: set to now() when the token is consumed.
    -- Presenting the same token a second time returns 401.
    used_at     TIMESTAMPTZ NULL,

    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT pk_password_reset_tokens PRIMARY KEY (id),
    CONSTRAINT uq_password_reset_tokens_hash UNIQUE (token_hash),
    CONSTRAINT fk_password_reset_tokens_user FOREIGN KEY (user_id)
        REFERENCES users (id)
        ON DELETE CASCADE
);

CREATE INDEX idx_password_reset_tokens_user_id
    ON password_reset_tokens (user_id);

COMMENT ON TABLE password_reset_tokens IS
    'Single-use, time-limited password reset tokens. Raw token sent via email; only hash stored.';
COMMENT ON COLUMN password_reset_tokens.used_at IS
    'NULL = not yet used. Set on first (and only) valid use. Second use returns 401.';
