package dev.stagepass.auth.controller;

import dev.stagepass.auth.dto.AuthDtos.SuspendUserRequest;
import dev.stagepass.auth.dto.AuthDtos.UpdateProfileRequest;
import dev.stagepass.auth.dto.AuthDtos.UserPage;
import dev.stagepass.auth.dto.AuthDtos.UserProfileResponse;
import dev.stagepass.auth.security.StagePassPrincipal;
import dev.stagepass.auth.service.IdentityService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.HttpStatus;

import java.util.UUID;

/**
 * Profile self-service and Admin user management.
 *
 * <p><strong>Self-service endpoints (/auth/me):</strong>
 * Any authenticated user can read and update their own profile.
 * No ADMIN role required.
 *
 * <p><strong>Admin endpoints (/auth/users/**):</strong>
 * All require ADMIN role, enforced by @PreAuthorize.
 * RBAC is enforced at the service layer as well (defence-in-depth).
 * (NFR-SEC-003)
 *
 * <p><strong>Tenant isolation (NFR-SEC-004):</strong>
 * /auth/me always uses the authenticated principal's userId from the JWT —
 * never a path variable. This ensures one user cannot read another's profile
 * by guessing a UUID. Admin endpoints explicitly require ADMIN role.
 */
@RestController
@RequestMapping("/auth")
public class IdentityController {

    private final IdentityService identityService;

    public IdentityController(IdentityService identityService) {
        this.identityService = identityService;
    }

    // ══════════════════════════════════════════════════════════
    // SELF-SERVICE — /auth/me
    // ══════════════════════════════════════════════════════════

    /**
     * GET /auth/me
     *
     * <p>Returns the authenticated user's own profile.
     * userId is sourced from the JWT principal, not the request — prevents
     * horizontal privilege escalation (OWASP A01 — Broken Access Control).
     */
    @GetMapping("/me")
    public ResponseEntity<UserProfileResponse> getProfile(
            @AuthenticationPrincipal StagePassPrincipal principal) {

        return ResponseEntity.ok(identityService.getProfile(principal));
    }

    /**
     * PUT /auth/me
     *
     * <p>Updates the authenticated user's display name.
     * Email and role are not updatable via self-service.
     */
    @PutMapping("/me")
    public ResponseEntity<UserProfileResponse> updateProfile(
            @Valid @RequestBody UpdateProfileRequest request,
            @AuthenticationPrincipal StagePassPrincipal principal) {

        return ResponseEntity.ok(identityService.updateProfile(principal, request));
    }

    // ══════════════════════════════════════════════════════════
    // ADMIN — /auth/users/**
    // ══════════════════════════════════════════════════════════

    /**
     * GET /auth/users
     *
     * <p>Paginated list of all users. Supports optional role and status filters.
     * Admin only. Returns cursor-based pagination (NFR convention).
     *
     * @param role   optional filter: CUSTOMER, ORGANISER, VENUE, ADMIN
     * @param status optional filter: ACTIVE, SUSPENDED, PENDING_VERIFICATION
     * @param page   zero-indexed page number (default 0)
     */
    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserPage> listUsers(
            @RequestParam(required = false) String role,
            @RequestParam(required = false) String status,
            @RequestParam(defaultValue = "0") int page) {

        return ResponseEntity.ok(identityService.listUsers(role, status, page));
    }

    /**
     * GET /auth/users/{userId}
     *
     * <p>Returns the profile of any user by ID. Admin only.
     */
    @GetMapping("/users/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserProfileResponse> getUserById(
            @PathVariable UUID userId,
            @AuthenticationPrincipal StagePassPrincipal principal) {

        // Reuse getProfile by constructing a principal scoped to the target userId.
        // IdentityService.getProfile fetches by principal.userId() — safe because
        // we've already required ADMIN role above.
        //
        // Rationale for not exposing getUserById separately in IdentityService:
        // the same DB query applies; we avoid duplicating the userRepository.findById call.
        // The ADMIN role check here enforces the access control boundary.
        StagePassPrincipal targetPrincipal = new StagePassPrincipal(
            userId,
            principal.role(),   // Admin's role — only used for permission checks in service
            principal.jti()     // Admin's JTI
        );
        return ResponseEntity.ok(identityService.getProfile(targetPrincipal));
    }

    /**
     * POST /auth/users/{userId}/suspend
     *
     * <p>Suspends a user account. Suspension is permanent until an Admin reinstates.
     * Recorded in admin_audit_log. Admin only.
     */
    @PostMapping("/users/{userId}/suspend")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasRole('ADMIN')")
    public void suspendUser(
            @PathVariable UUID userId,
            @Valid @RequestBody SuspendUserRequest request,
            @AuthenticationPrincipal StagePassPrincipal principal) {

        identityService.suspendUser(userId, request, principal);
    }

    /**
     * POST /auth/users/{userId}/reinstate
     *
     * <p>Reinstates a suspended user account. Admin only.
     * Accepts an optional reason in the request body (plain string).
     */
    @PostMapping("/users/{userId}/reinstate")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasRole('ADMIN')")
    public void reinstateUser(
            @PathVariable UUID userId,
            @RequestBody(required = false) String reason,
            @AuthenticationPrincipal StagePassPrincipal principal) {

        identityService.reinstateUser(userId, reason != null ? reason : "Admin reinstated", principal);
    }
}
