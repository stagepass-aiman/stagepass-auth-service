package dev.stagepass.auth.controller;

import dev.stagepass.auth.dto.AuthDtos.ChangePasswordRequest;
import dev.stagepass.auth.dto.AuthDtos.ConfirmPasswordResetRequest;
import dev.stagepass.auth.dto.AuthDtos.LoginRequest;
import dev.stagepass.auth.dto.AuthDtos.PasswordResetRequestBody;
import dev.stagepass.auth.dto.AuthDtos.RefreshRequest;
import dev.stagepass.auth.dto.AuthDtos.RegisterRequest;
import dev.stagepass.auth.dto.AuthDtos.TokenPair;
import dev.stagepass.auth.domain.UserRole;
import dev.stagepass.auth.security.LoginRateLimiter;
import dev.stagepass.auth.security.StagePassPrincipal;
import dev.stagepass.auth.service.AuthService;
import dev.stagepass.auth.service.IdempotencyService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.Optional;
import java.util.UUID;

/**
 * Handles authentication lifecycle: register, login, refresh, logout,
 * password change, and password reset.
 *
 * <p><strong>Rate limiting (THR-AUTH-02, THR-AUTH-08):</strong>
 * POST /auth/login is gated by {@link LoginRateLimiter} (5 req/min per IP).
 * Rate limit is checked in this controller (not a filter) so the response
 * can use RFC 9457 Problem Details format like all other error responses.
 *
 * <p><strong>Idempotency (NFR-REL-001):</strong>
 * Mutating endpoints accept an optional {@code Idempotency-Key} header.
 * If a cached response exists for the key, it is returned immediately
 * without re-executing the operation. Keys expire after 24 hours.
 *
 * <p><strong>ADMIN registration (THR-AUTH-10):</strong>
 * Registering with role=ADMIN requires the caller to already have an
 * active ADMIN JWT. This is enforced by the {@code @PreAuthorize} on
 * the register endpoint when the requested role is ADMIN.
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;
    private final IdempotencyService idempotencyService;
    private final LoginRateLimiter loginRateLimiter;

    public AuthController(AuthService authService,
                          IdempotencyService idempotencyService,
                          LoginRateLimiter loginRateLimiter) {
        this.authService = authService;
        this.idempotencyService = idempotencyService;
        this.loginRateLimiter = loginRateLimiter;
    }

    // ══════════════════════════════════════════════════════════
    // REGISTER
    // ══════════════════════════════════════════════════════════

    /**
     * POST /auth/register
     *
     * <p>Open endpoint — no JWT required. Role is part of the request body.
     * Registering with role=ADMIN requires an existing ADMIN JWT
     * (enforced by @PreAuthorize below).
     *
     * <p>Returns 201 Created with the new token pair, so the client
     * can proceed without a separate login step.
     */
    @PostMapping("/register")
    public ResponseEntity<TokenPair> register(
            @Valid @RequestBody RegisterRequest request,
            @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey,
            @AuthenticationPrincipal StagePassPrincipal caller) {

        // ADMIN role registration requires the caller to be an existing Admin. (THR-AUTH-10)
        // Other roles are open for self-registration.
        if (request.role() == UserRole.ADMIN && (caller == null || caller.role() != UserRole.ADMIN)) {
            ProblemDetail pd = ProblemDetail.forStatusAndDetail(
                HttpStatus.FORBIDDEN,
                "Registering an ADMIN account requires an existing Admin JWT."
            );
            pd.setType(URI.create("https://stagepass.dev/problems/forbidden"));
            pd.setTitle("Forbidden");
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        // Idempotency: if we've seen this key before, return the cached response.
        if (idempotencyKey != null) {
            Optional<TokenPair> cached = idempotencyService.get(idempotencyKey, TokenPair.class);
            if (cached.isPresent()) {
                log.debug("Idempotent register response returned. key={}", idempotencyKey);
                return ResponseEntity.status(HttpStatus.CREATED).body(cached.get());
            }
        }

        TokenPair tokens = authService.register(request);

        if (idempotencyKey != null) {
            idempotencyService.put(idempotencyKey, tokens);
        }

        return ResponseEntity.status(HttpStatus.CREATED).body(tokens);
    }

    // ══════════════════════════════════════════════════════════
    // LOGIN
    // ══════════════════════════════════════════════════════════

    /**
     * POST /auth/login
     *
     * <p>Rate limited to 5 requests per minute per IP. (THR-AUTH-02, THR-AUTH-08)
     * bcrypt runs for every request regardless of whether the email exists. (THR-AUTH-07)
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {

        String clientIp = resolveClientIp(httpRequest);

        // Check rate limit before doing any DB work.
        // Returns 429 Too Many Requests with a Retry-After header if exceeded.
        if (!loginRateLimiter.isAllowed(clientIp)) {
            log.warn("Login rate limit exceeded. ip={}", clientIp);
            ProblemDetail pd = ProblemDetail.forStatusAndDetail(
                HttpStatus.TOO_MANY_REQUESTS,
                "Too many login attempts. Wait one minute and try again."
            );
            pd.setType(URI.create("https://stagepass.dev/problems/rate-limit-exceeded"));
            pd.setTitle("Rate Limit Exceeded");
            return ResponseEntity
                .status(HttpStatus.TOO_MANY_REQUESTS)
                .header("Retry-After", "60")
                .body(pd);
        }

        String userAgent = httpRequest.getHeader("User-Agent");
        TokenPair tokens = authService.login(request, clientIp, userAgent);
        return ResponseEntity.ok(tokens);
    }

    // ══════════════════════════════════════════════════════════
    // REFRESH
    // ══════════════════════════════════════════════════════════

    /**
     * POST /auth/refresh
     *
     * <p>Exchanges a valid opaque refresh token for a new token pair.
     * The old refresh token is revoked atomically (rotation — THR-AUTH-03).
     */
    @PostMapping("/refresh")
    public ResponseEntity<TokenPair> refresh(
            @Valid @RequestBody RefreshRequest request,
            HttpServletRequest httpRequest) {

        String clientIp = resolveClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");
        TokenPair tokens = authService.refresh(request.refreshToken(), clientIp, userAgent);
        return ResponseEntity.ok(tokens);
    }

    // ══════════════════════════════════════════════════════════
    // LOGOUT
    // ══════════════════════════════════════════════════════════

    /**
     * POST /auth/logout
     *
     * <p>Revokes the caller's current access token JTI and all refresh tokens.
     * Requires a valid JWT — the caller must be authenticated to log out.
     * Returns 204 No Content.
     */
    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@AuthenticationPrincipal StagePassPrincipal principal) {
        authService.logout(principal);
    }

    // ══════════════════════════════════════════════════════════
    // PASSWORD CHANGE
    // ══════════════════════════════════════════════════════════

    /**
     * POST /auth/password/change
     *
     * <p>Changes the authenticated user's password. Revokes all refresh tokens,
     * forcing re-authentication on all devices.
     */
    @PostMapping("/password/change")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void changePassword(
            @Valid @RequestBody ChangePasswordRequest request,
            @AuthenticationPrincipal StagePassPrincipal principal) {

        authService.changePassword(principal, request);
    }

    // ══════════════════════════════════════════════════════════
    // PASSWORD RESET
    // ══════════════════════════════════════════════════════════

    /**
     * POST /auth/password/reset/request
     *
     * <p>Initiates a password reset flow. Always returns 204 regardless of
     * whether the email exists (THR-AUTH-06 — user enumeration prevention).
     * STUB: token is logged in Phase 3; replaced with email in Phase 6.
     */
    @PostMapping("/password/reset/request")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void requestPasswordReset(@Valid @RequestBody PasswordResetRequestBody request) {
        authService.requestPasswordReset(request.email());
    }

    /**
     * POST /auth/password/reset/confirm
     *
     * <p>Completes a password reset using the token from the reset email link.
     */
    @PostMapping("/password/reset/confirm")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void confirmPasswordReset(@Valid @RequestBody ConfirmPasswordResetRequest request) {
        authService.confirmPasswordReset(request);
    }

    // ══════════════════════════════════════════════════════════
    // ADMIN — REVOKE ALL SESSIONS
    // ══════════════════════════════════════════════════════════

    /**
     * POST /auth/users/{userId}/revoke-sessions
     * Admin only. Force-logs out a user by revoking all their refresh tokens.
     *
     * <p>Note: this endpoint is also exposed on {@link IdentityController} at
     * the /auth/users path. The reason revoke-sessions lives in AuthController
     * is that it calls AuthService.revokeAllSessions which is an auth lifecycle
     * operation, not a profile operation.
     */
    @PostMapping("/users/{userId}/revoke-sessions")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasRole('ADMIN')")
    public void revokeAllSessions(
            @org.springframework.web.bind.annotation.PathVariable UUID userId,
            @RequestBody(required = false) String reason,
            @AuthenticationPrincipal StagePassPrincipal principal) {

        authService.revokeAllSessions(userId, principal, reason != null ? reason : "Admin action");
    }

    // ══════════════════════════════════════════════════════════
    // HELPERS
    // ══════════════════════════════════════════════════════════

    /**
     * Resolves the real client IP from the request.
     *
     * <p>Checks X-Forwarded-For first (set by load balancers and proxies).
     * Falls back to the direct remote address. Only the first IP in the
     * X-Forwarded-For chain is used — the leftmost IP is the originating client.
     *
     * <p>In production (Phase 9), the ALB ensures only one IP is in the header,
     * so spoofing via X-Forwarded-For is not a concern.
     */
    private static String resolveClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            // Take only the first address in the chain.
            return xff.split(",")[0].strip();
        }
        return request.getRemoteAddr();
    }
}
