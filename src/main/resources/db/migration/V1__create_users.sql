-- ============================================================
-- V1__create_users.sql
-- Repo: stagepass-auth-service
-- Path: src/main/resources/db/migration/V1__create_users.sql
-- ============================================================
--
-- Creates the `users` table — the identity root of the platform.
--
-- Design decisions captured here:
--
-- 1. UUID primary key via gen_random_uuid() (pgcrypto extension).
--    Consistent with the "UUIDs everywhere" convention (Section 11).
--    We require pgcrypto — it is available in all modern PostgreSQL versions.
--
-- 2. email is UNIQUE and lowercase-normalised by a CHECK constraint.
--    We do NOT lower-case in application code because that is forgettable;
--    we lower-case at the DB boundary where it cannot be bypassed.
--    The application still normalises on write for belt-and-suspenders.
--
-- 3. failed_login_attempts + locked_until implement account lockout
--    as a property of the account, not a separate table.
--    A separate table would require a JOIN on every login hot path.
--    (Mitigates THR-AUTH-02)
--
-- 4. updated_at is maintained by a BEFORE UPDATE trigger, not
--    application code. Application code forgets; the DB does not.
--    The trigger is defined at the bottom of this migration.
--
-- 5. status CHECK constraint mirrors the UserStatus enum exactly.
--    If a new status is added to the enum, a new migration must
--    update this CHECK constraint simultaneously.
-- ============================================================

-- pgcrypto provides gen_random_uuid().
-- Available by default in PostgreSQL 13+.
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    -- Surrogate primary key. UUID prevents enumeration attacks —
    -- an attacker cannot guess the next user ID by incrementing.
    id                    UUID            NOT NULL DEFAULT gen_random_uuid(),

    -- Email is the unique identifier for login.
    -- max 254 chars per RFC 5321.
    email                 VARCHAR(254)    NOT NULL,

    -- bcrypt output. 60 chars for bcrypt; 72 chars gives headroom.
    -- NEVER stored as plaintext. NEVER logged. (NFR-SEC-007)
    password_hash         VARCHAR(72)     NOT NULL,

    -- Platform role. Disjoint — one role per user, ever.
    -- Mirrors the UserRole enum. (NFR-SEC-003)
    role                  VARCHAR(20)     NOT NULL,

    -- Account lifecycle status.
    status                VARCHAR(30)     NOT NULL DEFAULT 'ACTIVE',

    -- Display name shown in the UI. Not the legal name — no PII concern.
    display_name          VARCHAR(100)    NOT NULL,

    -- Failed consecutive login attempts for this account.
    -- Reset to 0 on successful login.
    -- Incremented on each failed login attempt.
    -- (Mitigates THR-AUTH-02)
    failed_login_attempts INTEGER         NOT NULL DEFAULT 0,

    -- When set, logins for this account are rejected until this timestamp.
    -- NULL means the account is not locked.
    -- Set when failed_login_attempts reaches the configured threshold (10).
    -- (Mitigates THR-AUTH-02)
    locked_until          TIMESTAMPTZ     NULL,

    -- Audit timestamps. Always UTC.

    version               BIGINT          NOT NULL DEFAULT 0,
    created_at            TIMESTAMPTZ     NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ     NOT NULL DEFAULT now(),

    CONSTRAINT pk_users PRIMARY KEY (id),

    -- Case-insensitive unique email constraint.
    -- We store emails exactly as provided but normalise on lookup.
    CONSTRAINT uq_users_email UNIQUE (email),

    -- Role must be one of the four platform roles.
    -- If you add a role, you must add a migration to update this constraint.
    CONSTRAINT ck_users_role CHECK (
        role IN ('CUSTOMER', 'ORGANISER', 'VENUE', 'ADMIN')
    ),

    -- Status values mirror the UserStatus enum.
    CONSTRAINT ck_users_status CHECK (
        status IN ('ACTIVE', 'SUSPENDED', 'PENDING_VERIFICATION')
    ),

    -- Display name cannot be blank whitespace.
    CONSTRAINT ck_users_display_name_not_blank CHECK (
        length(trim(display_name)) > 0
    ),

    -- Lockout counter cannot go negative.
    CONSTRAINT ck_users_failed_attempts_non_negative CHECK (
        failed_login_attempts >= 0
    )
);

-- ────────────────────────────────────────────────────────────
-- Indexes
-- ────────────────────────────────────────────────────────────

-- Login hot path: look up by email on every authentication attempt.
-- B-tree index on the email column.
-- The UNIQUE constraint already creates one; this is documented for clarity.
-- No additional index needed — the unique constraint index covers it.

-- Admin user management: filter by role and status.
CREATE INDEX idx_users_role ON users (role);
CREATE INDEX idx_users_status ON users (status);

-- ────────────────────────────────────────────────────────────
-- updated_at trigger
-- ────────────────────────────────────────────────────────────
--
-- This trigger fires BEFORE every UPDATE on users and sets
-- updated_at = now(). Application code must never set updated_at
-- directly — the trigger owns it.
--
-- WHY a trigger instead of application code:
-- Application code can bypass ORM lifecycle hooks (e.g. bulk updates,
-- native queries, direct JDBC). The trigger fires regardless of how
-- the update reaches PostgreSQL.

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();

-- ────────────────────────────────────────────────────────────
-- Comments (visible in psql \d+ users)
-- ────────────────────────────────────────────────────────────
COMMENT ON TABLE users IS
    'Platform user accounts. Identity root of StagePass. T1 — 99.9% SLO.';
COMMENT ON COLUMN users.password_hash IS
    'bcrypt hash, cost >= 12. Never stored or logged as plaintext. (NFR-SEC-007)';
COMMENT ON COLUMN users.failed_login_attempts IS
    'Resets to 0 on successful login. Increments on failure. Lockout at threshold. (THR-AUTH-02)';
COMMENT ON COLUMN users.locked_until IS
    'NULL = not locked. Non-null = reject login until this UTC timestamp. (THR-AUTH-02)';
