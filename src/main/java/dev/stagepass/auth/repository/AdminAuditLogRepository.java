package dev.stagepass.auth.repository;

import dev.stagepass.auth.domain.AdminAuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

/**
 * Repository for the append-only {@code admin_audit_log} table.
 *
 * <p><strong>Append-only enforcement at the application layer.</strong>
 * The delete and update methods inherited from JpaRepository are overridden
 * to throw {@link UnsupportedOperationException}. No service method should
 * ever call these — the overrides exist to catch accidental calls at runtime
 * and make the intent clear to future developers.
 *
 * <p>The DB layer enforces the same constraint via REVOKE in V4 migration.
 * Two layers of enforcement is intentional defence-in-depth.
 *
 * <p>Permitted operations: {@code save()} for new entries, {@code findAll()},
 * {@code findById()}, and the custom query methods below.
 */
@Repository
public interface AdminAuditLogRepository extends JpaRepository<AdminAuditLog, Long> {

    // ── Query methods ──────────────────────────────────────

    Page<AdminAuditLog> findByActorId(UUID actorId, Pageable pageable);
    Page<AdminAuditLog> findByTargetUserId(UUID targetUserId, Pageable pageable);

    // ── Append-only enforcement ────────────────────────────

    @Override
    default void deleteById(Long id) {
        throw new UnsupportedOperationException(
            "admin_audit_log is append-only. Deletion is not permitted. (THR-AUTH-11)");
    }

    @Override
    default void delete(AdminAuditLog entity) {
        throw new UnsupportedOperationException(
            "admin_audit_log is append-only. Deletion is not permitted. (THR-AUTH-11)");
    }

    @Override
    default void deleteAll() {
        throw new UnsupportedOperationException(
            "admin_audit_log is append-only. Deletion is not permitted. (THR-AUTH-11)");
    }

    @Override
    default void deleteAll(Iterable<? extends AdminAuditLog> entities) {
        throw new UnsupportedOperationException(
            "admin_audit_log is append-only. Deletion is not permitted. (THR-AUTH-11)");
    }

    @Override
    default void deleteAllById(Iterable<? extends Long> ids) {
        throw new UnsupportedOperationException(
            "admin_audit_log is append-only. Deletion is not permitted. (THR-AUTH-11)");
    }
}
