package dev.stagepass.auth.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

import java.time.Instant;
import java.util.UUID;

/**
 * JPA entity for the {@code users} table.
 *
 * <p><strong>No Lombok.</strong> All constructors and accessors are explicit.
 * Constructor injection only — no field injection anywhere.
 *
 * <p><strong>No @Builder.</strong> Use the static factory methods or the
 * package-private setters that the JPA runtime needs.
 *
 * <p><strong>updated_at</strong> is NOT managed by this entity — it is managed
 * by the {@code trg_users_updated_at} trigger in V1 migration. We read it
 * back after writes but never write it from Java.
 *
 * <p><strong>@Version</strong> enables optimistic locking for concurrent profile
 * updates. We do not use optimistic locking for the login path (that uses a
 * targeted UPDATE with a WHERE clause).
 */
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    /**
     * Optimistic locking version column.
     * Prevents lost-update anomalies when two requests modify the same user
     * concurrently (e.g. profile update + Admin suspend racing).
     */
    @Version
    @Column(name = "version", nullable = false)
    private Long version;

    @Column(name = "email", nullable = false, unique = true, length = 254)
    private String email;

    /**
     * bcrypt hash of the user's password. Cost ≥ 12. (NFR-SEC-007)
     * NEVER log this field. The @Column is non-nullable to force the
     * application to always supply a hash at insert time.
     */
    @Column(name = "password_hash", nullable = false, length = 72)
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false, length = 20)
    private UserRole role;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 30)
    private UserStatus status;

    @Column(name = "display_name", nullable = false, length = 100)
    private String displayName;

    /**
     * Count of consecutive failed login attempts.
     * Reset to 0 on each successful login.
     * Triggers lockout when it reaches the configured threshold.
     */
    @Column(name = "failed_login_attempts", nullable = false)
    private int failedLoginAttempts;

    /**
     * Null when the account is not locked.
     * Non-null when the account is temporarily locked due to failed attempts.
     * Lockout expires naturally when now() > lockedUntil.
     */
    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    /**
     * Managed by the DB trigger {@code trg_users_updated_at}.
     * Never set this from application code.
     */
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    /**
     * No-arg constructor required by JPA.
     * Do not use in application code — use the static factory.
     */
    protected User() {}

    /**
     * Factory method for creating a new user at registration time.
     *
     * @param email        normalised email address
     * @param passwordHash bcrypt hash of the raw password (cost ≥ 12)
     * @param role         assigned platform role
     * @param displayName  user-supplied display name
     */
    public static User create(String email, String passwordHash, UserRole role, String displayName) {
        var user = new User();
        user.email = email.toLowerCase().strip(); // Normalise before storing.
        user.passwordHash = passwordHash;
        user.role = role;
        user.status = UserStatus.ACTIVE;
        user.displayName = displayName.strip();
        user.failedLoginAttempts = 0;
        user.createdAt = Instant.now();
        user.updatedAt = Instant.now();
        return user;
    }

    // ──────────────────────────────────────────────
    // Domain behaviour (business logic on the entity)
    // ──────────────────────────────────────────────

    /**
     * Returns true if the account is currently locked out due to failed login attempts.
     * A lockout expires naturally; no active unlock is needed if lockedUntil is in the past.
     */
    public boolean isCurrentlyLocked() {
        return lockedUntil != null && Instant.now().isBefore(lockedUntil);
    }

    /**
     * Records a failed login attempt and applies lockout if the threshold is reached.
     *
     * @param maxAttempts      number of failures before lockout
     * @param lockoutDuration  duration of the lockout
     */
    public void recordFailedLoginAttempt(int maxAttempts, java.time.Duration lockoutDuration) {
        this.failedLoginAttempts++;
        if (this.failedLoginAttempts >= maxAttempts) {
            this.lockedUntil = Instant.now().plus(lockoutDuration);
        }
    }

    /** Resets the failed login counter and clears any lockout on successful authentication. */
    public void resetFailedLoginAttempts() {
        this.failedLoginAttempts = 0;
        this.lockedUntil = null;
    }

    /** Admin action: suspend this account. Does not revoke tokens — call AuthService.revokeAllSessions() separately. */
    public void suspend() {
        this.status = UserStatus.SUSPENDED;
    }

    /** Admin action: reinstate a suspended account. */
    public void reinstate() {
        this.status = UserStatus.ACTIVE;
        resetFailedLoginAttempts();
    }

    // ──────────────────────────────────────────────
    // Accessors — explicit getters only (no setters exposed outside domain)
    // ──────────────────────────────────────────────

    public UUID getId() { return id; }
    public String getEmail() { return email; }
    public String getPasswordHash() { return passwordHash; }
    public UserRole getRole() { return role; }
    public UserStatus getStatus() { return status; }
    public String getDisplayName() { return displayName; }
    public int getFailedLoginAttempts() { return failedLoginAttempts; }
    public Instant getLockedUntil() { return lockedUntil; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }

    // Package-private setters for JPA and controlled domain mutations only.
    void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }
    void setDisplayName(String displayName) { this.displayName = displayName.strip(); }
    void setRole(UserRole role) { this.role = role; }

    /**
     * Expose a controlled setter for display name to the service layer.
     * Named distinctly to make it clear this is a domain operation.
     */
    public void updateDisplayName(String displayName) {
        this.displayName = displayName.strip();
    }

    /**
     * Controlled setter for password hash — only called from AuthService
     * during password change flow.
     */
    public void changePasswordHash(String newHash) {
        this.passwordHash = newHash;
    }

    @Override
    public String toString() {
        // NEVER include passwordHash in toString — accidental logging risk.
        return "User{id=" + id + ", email=" + email + ", role=" + role + ", status=" + status + "}";
    }
}
