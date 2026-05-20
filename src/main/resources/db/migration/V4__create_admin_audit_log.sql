-- ============================================================
-- V4__create_admin_audit_log.sql
-- ============================================================
--
-- Immutable audit trail for Admin-performed actions.
-- Addresses THR-AUTH-11 (Repudiation threat).
--
-- Design decisions:
--
-- 1. BIGSERIAL primary key, not UUID.
--    BIGSERIAL gives a monotonically increasing sequence owned by the DB.
--    - Forensic reconstruction: "show me rows 4821–4850" is unambiguous.
--    - Gap detection: missing row 4822 is visible; UUID gaps are invisible.
--    - This is the only table in auth_db that deviates from UUID PKs.
--      The deviation is intentional and documented in the STRIDE model.
--
-- 2. actor_jti ties each audit entry to a specific JWT, not just a userId.
--    If an Admin account is compromised and used by an attacker, the
--    specific token used for each action is recorded.
--
-- 3. actor_id FK uses ON DELETE RESTRICT — Admin users cannot be deleted
--    if they have audit log entries. This preserves forensic integrity.
--    target_user_id uses ON DELETE SET NULL — the target user can be
--    deleted (soft or hard), but the audit entry remains with a null target.
--
-- 4. DB-level REVOKE prevents DELETE and UPDATE via SQL even if a developer
--    inadvertently adds a deleteById() call in Java code.
--    This is a defence-in-depth control on top of the Java-layer restriction
--    in AdminAuditLogRepository.
-- ============================================================

CREATE TABLE admin_audit_log (
    -- BIGSERIAL: monotonically increasing, DB-owned sequence.
    -- See design decision 1 above.
    id              BIGSERIAL       NOT NULL,

    -- The Admin who performed the action.
    -- FK references users(id) with RESTRICT — Admin cannot be deleted
    -- if they have audit entries.
    actor_id        UUID            NOT NULL,

    -- The jti claim from the JWT used to make the request.
    -- UUID format: 36 chars (8-4-4-4-12 with hyphens).
    actor_jti       VARCHAR(36)     NOT NULL,

    -- Semantic action type. Matches the operation performed.
    -- Examples: SUSPEND_USER, REINSTATE_USER, REVOKE_ALL_SESSIONS,
    --           CHANGE_USER_ROLE, FORCE_PASSWORD_RESET
    action_type     VARCHAR(100)    NOT NULL,

    -- The user account that was acted upon. Nullable for non-user actions.
    -- ON DELETE SET NULL: target user can be deleted without losing the audit entry.
    target_user_id  UUID            NULL,

    -- Admin-provided reason for the action. Captured from request body.
    reason          VARCHAR(500)    NULL,

    -- Structured context: IP address of the Admin, request summary, etc.
    -- JSONB for queryability.
    metadata        JSONB           NULL,

    -- Always UTC. DB-generated — not application-supplied.
    -- Application cannot manipulate the timestamp.
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),

    CONSTRAINT pk_admin_audit_log PRIMARY KEY (id),
    CONSTRAINT fk_audit_actor FOREIGN KEY (actor_id)
        REFERENCES users (id)
        ON DELETE RESTRICT,          -- Prevents deleting admins with audit history.
    CONSTRAINT fk_audit_target FOREIGN KEY (target_user_id)
        REFERENCES users (id)
        ON DELETE SET NULL           -- Target user deletion nulls the reference, not the row.
);

-- ────────────────────────────────────────────────────────────
-- Indexes
-- ────────────────────────────────────────────────────────────

-- Query by acting Admin (e.g. "show all actions by Admin X").
CREATE INDEX idx_audit_actor_id ON admin_audit_log (actor_id);

-- Query by affected user (e.g. "show all actions against User Y").
CREATE INDEX idx_audit_target_user_id ON admin_audit_log (target_user_id)
    WHERE target_user_id IS NOT NULL;

-- Time-range queries for audit review UI.
CREATE INDEX idx_audit_created_at ON admin_audit_log (created_at);

-- ────────────────────────────────────────────────────────────
-- APPEND-ONLY enforcement at the DB level (THR-AUTH-11)
-- ────────────────────────────────────────────────────────────
--
-- REVOKE DELETE and UPDATE from PUBLIC so that the application role
-- (auth_user) cannot issue DELETE or UPDATE statements against this table,
-- even if a developer adds one by mistake.
--
-- SELECT and INSERT remain permitted.
-- Only a superuser (DBA) can bypass this.
--
-- In the local Docker Compose setup, auth_user is the application role.
-- In production (Phase 9), the Vault-issued dynamic credentials also
-- exclude DELETE and UPDATE on this table via a PostgreSQL role policy.
--
REVOKE DELETE, UPDATE, TRUNCATE ON TABLE admin_audit_log FROM PUBLIC;

COMMENT ON TABLE admin_audit_log IS
    'Append-only Admin action audit trail. BIGSERIAL PK for monotonic ordering. No DELETE, no UPDATE. (THR-AUTH-11)';
COMMENT ON COLUMN admin_audit_log.id IS
    'BIGSERIAL — monotonically increasing DB sequence. Gap detection possible. (See V4 migration rationale)';
COMMENT ON COLUMN admin_audit_log.actor_jti IS
    'jti claim from the JWT used for this action. Ties the action to a specific token, not just a userId.';
