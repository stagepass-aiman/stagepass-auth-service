package dev.stagepass.auth.repository;

import dev.stagepass.auth.domain.User;
import dev.stagepass.auth.domain.UserRole;
import dev.stagepass.auth.domain.UserStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    /** Admin: list users with optional role/status filters. Cursor pagination via Page. */
    Page<User> findByRoleAndStatus(UserRole role, UserStatus status, Pageable pageable);
    Page<User> findByRole(UserRole role, Pageable pageable);
    Page<User> findByStatus(UserStatus status, Pageable pageable);

    /**
     * Targeted failed-attempt reset — uses a native UPDATE to avoid loading the
     * entity, modifying it in memory, and re-persisting. The @Version field is
     * not incremented by this query (intentional: lockout state is not a
     * business-significant version change that should cause optimistic locking conflicts).
     */
    @Modifying
    @Query("UPDATE User u SET u.failedLoginAttempts = 0, u.lockedUntil = NULL WHERE u.id = :id")
    void resetLockout(@Param("id") UUID id);
}
