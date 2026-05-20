package dev.stagepass.auth.service;

import dev.stagepass.auth.domain.AdminAuditLog;
import dev.stagepass.auth.domain.User;
import dev.stagepass.auth.domain.UserRole;
import dev.stagepass.auth.domain.UserStatus;
import dev.stagepass.auth.dto.AuthDtos.SuspendUserRequest;
import dev.stagepass.auth.dto.AuthDtos.UpdateProfileRequest;
import dev.stagepass.auth.dto.AuthDtos.UserPage;
import dev.stagepass.auth.dto.AuthDtos.UserProfileResponse;
import dev.stagepass.auth.exception.UserNotFoundException;
import dev.stagepass.auth.repository.AdminAuditLogRepository;
import dev.stagepass.auth.repository.RefreshTokenRepository;
import dev.stagepass.auth.repository.UserRepository;
import dev.stagepass.auth.security.StagePassPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * User profile and identity management.
 * Handles self-service profile operations (GET/PUT /auth/me)
 * and Admin user management (/auth/users/**).
 */
@Service
public class IdentityService {

    private static final Logger log = LoggerFactory.getLogger(IdentityService.class);

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AdminAuditLogRepository auditLogRepository;

    public IdentityService(UserRepository userRepository,
                           RefreshTokenRepository refreshTokenRepository,
                           AdminAuditLogRepository auditLogRepository) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.auditLogRepository = auditLogRepository;
    }

    // ══════════════════════════════════════════════════════════
    // SELF-SERVICE PROFILE
    // ══════════════════════════════════════════════════════════

    @Transactional(readOnly = true)
    public UserProfileResponse getProfile(StagePassPrincipal principal) {
        User user = userRepository.findById(principal.userId())
            .orElseThrow(() -> new UserNotFoundException(principal.userId().toString()));
        return toResponse(user);
    }

    @Transactional
    public UserProfileResponse updateProfile(StagePassPrincipal principal, UpdateProfileRequest request) {
        User user = userRepository.findById(principal.userId())
            .orElseThrow(() -> new UserNotFoundException(principal.userId().toString()));

        user.updateDisplayName(request.displayName());
        userRepository.save(user);

        log.info("Profile updated. userId={}", principal.userId());
        return toResponse(user);
    }

    // ══════════════════════════════════════════════════════════
    // ADMIN: USER LISTING
    // ══════════════════════════════════════════════════════════

    /**
     * Lists all users with optional role and status filters.
     * Page size is fixed at 50 for Phase 3 — cursor pagination deferred.
     */
    @Transactional(readOnly = true)
    @PreAuthorize("hasRole('ADMIN')")
    public UserPage listUsers(String role, String status, int page) {
        int pageSize = 50;
        PageRequest pageRequest = PageRequest.of(page, pageSize, Sort.by("createdAt").descending());

        Page<User> result;
        if (role != null && status != null) {
            result = userRepository.findByRoleAndStatus(
                UserRole.valueOf(role), UserStatus.valueOf(status), pageRequest);
        } else if (role != null) {
            result = userRepository.findByRole(UserRole.valueOf(role), pageRequest);
        } else if (status != null) {
            result = userRepository.findByStatus(UserStatus.valueOf(status), pageRequest);
        } else {
            result = userRepository.findAll(pageRequest);
        }

        List<UserProfileResponse> items = result.getContent().stream()
            .map(IdentityService::toResponse)
            .toList();

        // Simple page-number-based cursors for Phase 3.
        // Replace with keyset/cursor-based pagination in Phase 9 for performance at scale.
        String nextCursor = result.hasNext() ? String.valueOf(page + 1) : null;
        String prevCursor = page > 0 ? String.valueOf(page - 1) : null;

        return new UserPage(items, nextCursor, prevCursor);
    }

    // ══════════════════════════════════════════════════════════
    // ADMIN: SUSPEND / REINSTATE
    // ══════════════════════════════════════════════════════════

    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public void suspendUser(UUID targetUserId, SuspendUserRequest request, StagePassPrincipal admin) {
        User user = userRepository.findById(targetUserId)
            .orElseThrow(() -> new UserNotFoundException(targetUserId.toString()));

        user.suspend();
        userRepository.save(user);

        // Revoke all refresh tokens immediately — suspended users cannot use existing sessions.
        refreshTokenRepository.revokeAllByUserId(targetUserId, Instant.now());

        // Append audit entry (THR-AUTH-11).
        auditLogRepository.save(AdminAuditLog.of(
            admin.userId(), admin.jti(), "SUSPEND_USER", targetUserId, request.reason()
        ));

        log.info("User suspended. targetUserId={} by adminId={}", targetUserId, admin.userId());
    }

    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public void reinstateUser(UUID targetUserId, String reason, StagePassPrincipal admin) {
        User user = userRepository.findById(targetUserId)
            .orElseThrow(() -> new UserNotFoundException(targetUserId.toString()));

        user.reinstate();
        userRepository.save(user);

        auditLogRepository.save(AdminAuditLog.of(
            admin.userId(), admin.jti(), "REINSTATE_USER", targetUserId, reason
        ));

        log.info("User reinstated. targetUserId={} by adminId={}", targetUserId, admin.userId());
    }

    // ── Helper ────────────────────────────────────────────────

    private static UserProfileResponse toResponse(User user) {
        return new UserProfileResponse(
            user.getId().toString(),
            user.getEmail(),
            user.getRole().name(),
            user.getDisplayName(),
            user.getStatus().name(),
            user.getCreatedAt().toString(),
            user.getUpdatedAt() != null ? user.getUpdatedAt().toString() : null
        );
    }
}
