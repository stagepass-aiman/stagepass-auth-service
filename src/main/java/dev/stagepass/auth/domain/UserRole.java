package dev.stagepass.auth.domain;

/**
 * Platform roles for StagePass users.
 *
 * <p>Roles are disjoint — one user has exactly one role, always.
 * Role assignment happens at registration and can only be changed by an ADMIN.
 *
 * <p>These values are stored as VARCHAR(20) in PostgreSQL (CHECK constraint in V1 migration).
 * If you add a role here, you MUST add a migration to update the CHECK constraint.
 * (NFR-SEC-003: RBAC enforced at service layer.)
 *
 * <p>Spring Security role convention: ROLE_ prefix is added by
 * {@code SimpleGrantedAuthority}. The value stored in the JWT 'role' claim
 * is the enum name without the prefix (e.g. "CUSTOMER", not "ROLE_CUSTOMER").
 */
public enum UserRole {

    /** End customer: discovers events, books tickets, manages personal bookings. */
    CUSTOMER,

    /** Event creator: creates events at booked venues, manages ticket inventory. */
    ORGANISER,

    /** Venue owner: lists spaces, responds to booking requests. */
    VENUE,

    /**
     * Platform operator: full administrative access.
     * ADMIN registration is gated — requires an existing ADMIN JWT.
     */
    ADMIN
}
