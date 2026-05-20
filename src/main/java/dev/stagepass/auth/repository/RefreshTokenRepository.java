package dev.stagepass.auth.repository;

import dev.stagepass.auth.domain.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    /** Primary lookup — find a token by its SHA-256 hash. */
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    /** Find all active (non-revoked, non-expired) tokens for a user. */
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.user.id = :userId " +
           "AND rt.revokedAt IS NULL AND rt.expiresAt > :now")
    List<RefreshToken> findActiveTokensByUserId(@Param("userId") UUID userId,
                                                 @Param("now") Instant now);

    /**
     * Bulk-revoke all refresh tokens for a user.
     * Used during:
     *   - Password change (NFR: revoke all existing sessions)
     *   - Admin suspend (tokens revoked immediately)
     *   - Admin revoke-all-sessions endpoint
     * Returns the number of tokens updated.
     */
    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revokedAt = :now " +
           "WHERE rt.user.id = :userId AND rt.revokedAt IS NULL")
    int revokeAllByUserId(@Param("userId") UUID userId, @Param("now") Instant now);

    /**
     * Periodic cleanup: delete expired and revoked tokens older than retention window.
     * Called by a scheduled task (not implemented in Phase 3 — deferred).
     */
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiresAt < :cutoff")
    void deleteExpiredBefore(@Param("cutoff") Instant cutoff);
}
