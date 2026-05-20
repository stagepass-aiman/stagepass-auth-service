package dev.stagepass.auth.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * JPA entity for the {@code admin_audit_log} table.
 *
 * <p><strong>Append-only by design.</strong> This entity is a forensic record.
 * No update or delete methods are exposed. The repository layer enforces this
 * at the application level; the DB enforces it via REVOKE in V4 migration.
 *
 * <p><strong>BIGSERIAL primary key</strong> (not UUID). Rationale: monotonically
 * increasing sequence owned by the DB. Gaps indicate deleted rows (a forensic signal).
 * UUIDs are random — gaps are invisible. This is the only table in auth_db
 * that deviates from the UUID-everywhere convention.
 *
 * <p><strong>No @ManyToOne relationships.</strong> actor_id and target_user_id are
 * stored as plain UUIDs. We do not load User entities when writing audit entries —
 * that would create an unnecessary dependency on the users table at write time.
 * FK constraints are enforced at the DB level in V4 migration.
 */
@Entity
@Table(name = "admin_audit_log")
public class AdminAuditLog {

    /**
     * BIGSERIAL — monotonically increasing DB sequence.
     * GenerationType.IDENTITY maps to PostgreSQL's BIGSERIAL.
     * Never use UUID here. See class Javadoc.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", updatable = false, nullable = false)
    private Long id;

    /** UUID of the Admin who performed the action. */
    @Column(name = "actor_id", nullable = false, updatable = false)
    private UUID actorId;

    /**
     * The jti claim from the JWT used to perform the action.
     * Ties this audit entry to a specific token, not just a userId.
     * Critical if Admin credentials are ever shared (which they should not be).
     */
    @Column(name = "actor_jti", nullable = false, updatable = false, length = 36)
    private String actorJti;

    /**
     * Semantic action type.
     * Examples: SUSPEND_USER, REINSTATE_USER, REVOKE_ALL_SESSIONS.
     * Use SCREAMING_SNAKE_CASE consistently.
     */
    @Column(name = "action_type", nullable = false, updatable = false, length = 100)
    private String actionType;

    /** UUID of the affected user. Null for platform-level actions. */
    @Column(name = "target_user_id", updatable = false)
    private UUID targetUserId;

    /** Admin-supplied reason for the action. */
    @Column(name = "reason", updatable = false, length = 500)
    private String reason;

    /**
     * Structured metadata: request IP, summary of changes.
     * Stored as JSONB in PostgreSQL; mapped as String here — no need for
     * a dedicated JSONB converter for this Phase 3 implementation.
     * Upgrade to JSONB type mapping if queryability is required in Phase 10.
     */
    @Column(name = "metadata", updatable = false, columnDefinition = "jsonb")
    private String metadata;

    /**
     * DB-generated timestamp. The application supplies nothing for this field —
     * it is set by PostgreSQL's DEFAULT now(). Marked as insertable=false
     * so Hibernate does not attempt to insert a value.
     */
    @Column(name = "created_at", updatable = false, insertable = false)
    private Instant createdAt;

    /** JPA no-arg constructor. Do not use in application code. */
    protected AdminAuditLog() {}

    /**
     * Factory method — the only way to create an audit log entry.
     * All parameters are required (no optional fields in the factory).
     */
    public static AdminAuditLog of(UUID actorId, String actorJti, String actionType,
                                   UUID targetUserId, String reason) {
        var entry = new AdminAuditLog();
        entry.actorId = actorId;
        entry.actorJti = actorJti;
        entry.actionType = actionType;
        entry.targetUserId = targetUserId;
        entry.reason = reason;
        return entry;
    }

    // ── Accessors — read-only ──────────────────────────────

    public Long getId() { return id; }
    public UUID getActorId() { return actorId; }
    public String getActorJti() { return actorJti; }
    public String getActionType() { return actionType; }
    public UUID getTargetUserId() { return targetUserId; }
    public String getReason() { return reason; }
    public Instant getCreatedAt() { return createdAt; }
}
