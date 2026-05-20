package dev.stagepass.auth.domain;

/**
 * Lifecycle status for a user account.
 *
 * <p>Stored as VARCHAR(30) in PostgreSQL with a CHECK constraint (V1 migration).
 * Adding a new status requires a migration to update the CHECK constraint.
 */
public enum UserStatus {

    /** Account is active and can authenticate normally. */
    ACTIVE,

    /**
     * Account has been administratively suspended.
     * Login attempts return 401. Suspension reason is logged in admin_audit_log.
     * Reinstated by an ADMIN via POST /auth/users/{id}/reinstate.
     */
    SUSPENDED,

    /**
     * Account created but email not yet verified.
     * Placeholder for a future email verification flow.
     * Currently, all new accounts start as ACTIVE (verification not implemented in Phase 3).
     */
    PENDING_VERIFICATION
}
