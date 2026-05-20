package dev.stagepass.auth.service;

import dev.stagepass.auth.config.AppProperties;
import dev.stagepass.auth.domain.AdminAuditLog;
import dev.stagepass.auth.domain.PasswordResetToken;
import dev.stagepass.auth.domain.RefreshToken;
import dev.stagepass.auth.domain.User;
import dev.stagepass.auth.domain.UserRole;
import dev.stagepass.auth.dto.AuthDtos.ChangePasswordRequest;
import dev.stagepass.auth.dto.AuthDtos.ConfirmPasswordResetRequest;
import dev.stagepass.auth.dto.AuthDtos.LoginRequest;
import dev.stagepass.auth.dto.AuthDtos.RegisterRequest;
import dev.stagepass.auth.dto.AuthDtos.TokenPair;
import dev.stagepass.auth.exception.AccountLockedException;
import dev.stagepass.auth.exception.AccountSuspendedException;
import dev.stagepass.auth.exception.EmailAlreadyRegisteredException;
import dev.stagepass.auth.exception.InvalidCredentialsException;
import dev.stagepass.auth.exception.PasswordResetTokenInvalidException;
import dev.stagepass.auth.exception.TokenRevokedException;
import dev.stagepass.auth.exception.UserNotFoundException;
import dev.stagepass.auth.repository.AdminAuditLogRepository;
import dev.stagepass.auth.repository.PasswordResetTokenRepository;
import dev.stagepass.auth.repository.RefreshTokenRepository;
import dev.stagepass.auth.repository.UserRepository;
import dev.stagepass.auth.security.JtiBlocklistService;
import dev.stagepass.auth.security.JwtService;
import dev.stagepass.auth.security.StagePassPrincipal;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Core authentication business logic.
 *
 * <p>All methods that write to the DB are {@link Transactional}.
 * Read-only queries are annotated {@code @Transactional(readOnly=true)} to allow
 * the JPA provider and connection pool to optimise (e.g. read replicas in Phase 9).
 *
 * <p><strong>TIMING ATTACK PREVENTION (THR-AUTH-07):</strong>
 * The {@link #login} method ALWAYS runs bcrypt regardless of whether the email exists.
 * {@link #dummyHash} is computed in {@link #initDummyHash()} and used when no user
 * is found. This makes "email not found" take the same time as "wrong password".
 * Without this, an attacker can enumerate valid email addresses by measuring response time.
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final AdminAuditLogRepository auditLogRepository;
    private final JwtService jwtService;
    private final JtiBlocklistService jtiBlocklistService;
    private final PasswordEncoder passwordEncoder;
    private final AppProperties appProperties;

    /**
     * Pre-computed dummy bcrypt hash. Used during login when the email does not exist,
     * to ensure constant-time response regardless of user existence. (THR-AUTH-07)
     * Computed once at startup in {@link #initDummyHash()} — not as a static field,
     * because BCryptPasswordEncoder is a Spring bean (not statically accessible).
     */
    private String dummyHash;

    public AuthService(UserRepository userRepository,
                       RefreshTokenRepository refreshTokenRepository,
                       PasswordResetTokenRepository passwordResetTokenRepository,
                       AdminAuditLogRepository auditLogRepository,
                       JwtService jwtService,
                       JtiBlocklistService jtiBlocklistService,
                       PasswordEncoder passwordEncoder,
                       AppProperties appProperties) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordResetTokenRepository = passwordResetTokenRepository;
        this.auditLogRepository = auditLogRepository;
        this.jwtService = jwtService;
        this.jtiBlocklistService = jtiBlocklistService;
        this.passwordEncoder = passwordEncoder;
        this.appProperties = appProperties;
    }

    /**
     * Computes the dummy bcrypt hash at application startup.
     * The hash is of a random string — different on every restart, which is correct.
     * We don't want a fixed dummy hash that an attacker could pre-compute against.
     */
    @PostConstruct
    void initDummyHash() {
        this.dummyHash = passwordEncoder.encode(
            "StagePass-dummy-" + UUID.randomUUID()
        );
        log.info("Dummy bcrypt hash initialised for timing attack prevention. (THR-AUTH-07)");
    }

    // ══════════════════════════════════════════════════════════
    // REGISTER
    // ══════════════════════════════════════════════════════════

    /**
     * Registers a new user account.
     *
     * <p>ADMIN registration requires a valid ADMIN JWT — enforced at the controller layer
     * by checking the caller's role. Non-admin callers cannot register with role=ADMIN.
     *
     * @throws EmailAlreadyRegisteredException if the email is already in use
     */
    @Transactional
    public TokenPair register(RegisterRequest request) {
        String normalisedEmail = request.email().toLowerCase().strip();

        if (userRepository.existsByEmail(normalisedEmail)) {
            throw new EmailAlreadyRegisteredException();
        }

        String hash = passwordEncoder.encode(request.password());
        User user = User.create(normalisedEmail, hash, request.role(), request.displayName());
        userRepository.save(user);

        log.info("User registered. userId={} role={}", user.getId(), user.getRole());
        return issueTokenPair(user, null, null);
    }

    // ══════════════════════════════════════════════════════════
    // LOGIN
    // ══════════════════════════════════════════════════════════

    /**
     * Authenticates a user and returns a new token pair.
     *
     * <p><strong>Timing attack prevention (THR-AUTH-07):</strong>
     * {@code passwordEncoder.matches()} is called with the real hash if the user exists,
     * or {@code dummyHash} if the user does not exist. Either way, bcrypt runs.
     * The response time is identical whether the email exists or not.
     *
     * @param request         login credentials
     * @param issuedFromIp    client IP for refresh token metadata
     * @param userAgent       User-Agent header for refresh token metadata
     */
    @Transactional
    public TokenPair login(LoginRequest request, String issuedFromIp, String userAgent) {
        String normalisedEmail = request.email().toLowerCase().strip();
        var userOpt = userRepository.findByEmail(normalisedEmail);

        // ── TIMING ATTACK PREVENTION ────────────────────────────────────────────
        // ALWAYS run bcrypt — even if the user does not exist.
        // If user exists: verify against their real hash.
        // If user absent: verify against the dummy hash (always fails — intentional).
        // This ensures response time is the same for valid and invalid emails.
        // (THR-AUTH-07)
        String hashToVerify = userOpt
            .map(User::getPasswordHash)
            .orElse(dummyHash);

        boolean passwordMatches = passwordEncoder.matches(request.password(), hashToVerify);
        // ── END TIMING ATTACK PREVENTION ────────────────────────────────────────

        if (userOpt.isEmpty() || !passwordMatches) {
            // Record the failed attempt only for real accounts (avoids noise for enumeration attempts).
            userOpt.ifPresent(u -> {
                u.recordFailedLoginAttempt(
                    appProperties.lockout().maxAttempts(),
                    Duration.ofMinutes(appProperties.lockout().durationMinutes())
                );
                userRepository.save(u);
            });
            // Same message for both cases — do not leak whether email exists. (THR-AUTH-06)
            throw new InvalidCredentialsException();
        }

        User user = userOpt.get();

        // Check lockout AFTER bcrypt — if we checked before, an attacker could time
        // the absence of bcrypt to detect locked accounts.
        if (user.isCurrentlyLocked()) {
            throw new AccountLockedException(user.getLockedUntil());
        }

        if (user.getStatus() == dev.stagepass.auth.domain.UserStatus.SUSPENDED) {
            throw new AccountSuspendedException();
        }

        // Successful login — reset the failed attempt counter.
        user.resetFailedLoginAttempts();
        userRepository.save(user);

        log.info("User authenticated. userId={} role={}", user.getId(), user.getRole());
        return issueTokenPair(user, issuedFromIp, userAgent);
    }

    // ══════════════════════════════════════════════════════════
    // REFRESH
    // ══════════════════════════════════════════════════════════

    /**
     * Rotates a refresh token and issues a new token pair.
     *
     * <p><strong>Rotation-on-use (THR-AUTH-03):</strong>
     * The presented refresh token is revoked and a new one issued in the same
     * transaction. If the old token is presented again (replay attack), it is
     * already revoked → 401.
     *
     * @throws TokenRevokedException if the token is not found, already revoked, or expired
     */
    @Transactional
    public TokenPair refresh(String rawRefreshToken, String issuedFromIp, String userAgent) {
        String tokenHash = sha256Hex(rawRefreshToken);
        RefreshToken existingToken = refreshTokenRepository.findByTokenHash(tokenHash)
            .orElseThrow(TokenRevokedException::new);

        if (!existingToken.isActive()) {
            throw new TokenRevokedException();
        }

        User user = existingToken.getUser();

        if (user.getStatus() == dev.stagepass.auth.domain.UserStatus.SUSPENDED) {
            throw new AccountSuspendedException();
        }

        // Revoke the old token atomically in the same transaction as the new token insert.
        existingToken.revoke();
        refreshTokenRepository.save(existingToken);

        log.info("Refresh token rotated. userId={}", user.getId());
        return issueTokenPair(user, issuedFromIp, userAgent);
    }

    // ══════════════════════════════════════════════════════════
    // LOGOUT
    // ══════════════════════════════════════════════════════════

    /**
     * Logs out the current user by revoking their current access token's JTI
     * and all their refresh tokens.
     */
    @Transactional
    public void logout(StagePassPrincipal principal) {
        // Revoke the access token JTI immediately — anyone who has the token
        // cannot use it again once it appears in the blocklist.
        // TTL = full access token TTL (conservative upper bound — we don't know remaining time).
        jtiBlocklistService.revoke(principal.jti(), jwtService.getAccessTokenTtlSeconds());

        // Revoke all refresh tokens for this user (covers all active sessions/devices).
        int revoked = refreshTokenRepository.revokeAllByUserId(principal.userId(), Instant.now());

        log.info("User logged out. userId={} refreshTokensRevoked={}", principal.userId(), revoked);
    }

    // ══════════════════════════════════════════════════════════
    // REVOKE ALL SESSIONS (Admin action)
    // ══════════════════════════════════════════════════════════

    /**
     * Admin action: revoke all refresh tokens for a user.
     * The Admin's own JTI and reason are recorded in the audit log.
     */
    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public void revokeAllSessions(UUID targetUserId, StagePassPrincipal admin, String reason) {
        if (!userRepository.existsById(targetUserId)) {
            throw new UserNotFoundException(targetUserId.toString());
        }

        int revoked = refreshTokenRepository.revokeAllByUserId(targetUserId, Instant.now());

        auditLogRepository.save(AdminAuditLog.of(
            admin.userId(), admin.jti(), "REVOKE_ALL_SESSIONS", targetUserId, reason
        ));

        log.info("All sessions revoked. targetUserId={} by adminId={} count={}",
            targetUserId, admin.userId(), revoked);
    }

    // ══════════════════════════════════════════════════════════
    // CHANGE PASSWORD
    // ══════════════════════════════════════════════════════════

    /**
     * Changes the authenticated user's password.
     * Revokes all existing refresh tokens (forces re-login on all devices).
     */
    @Transactional
    public void changePassword(StagePassPrincipal principal, ChangePasswordRequest request) {
        User user = userRepository.findById(principal.userId())
            .orElseThrow(() -> new UserNotFoundException(principal.userId().toString()));

        if (!passwordEncoder.matches(request.currentPassword(), user.getPasswordHash())) {
            throw new InvalidCredentialsException();
        }

        String newHash = passwordEncoder.encode(request.newPassword());
        user.changePasswordHash(newHash);
        userRepository.save(user);

        // Revoke all refresh tokens — user must re-authenticate on all devices.
        refreshTokenRepository.revokeAllByUserId(principal.userId(), Instant.now());

        // Revoke current access token JTI.
        jtiBlocklistService.revoke(principal.jti(), jwtService.getAccessTokenTtlSeconds());

        log.info("Password changed. userId={}", principal.userId());
    }

    // ══════════════════════════════════════════════════════════
    // PASSWORD RESET
    // ══════════════════════════════════════════════════════════

    /**
     * Issues a password reset token for the given email.
     *
     * <p><strong>User enumeration prevention:</strong> always returns 204,
     * even if the email is not registered. The caller cannot tell if the
     * email exists or not. (THR-AUTH-06)
     *
     * <p><strong>Email sending:</strong> STUB in Phase 3.
     * The token is logged at INFO level. Replace with Notification Service call
     * when the email service is available (Phase 6).
     */
    @Transactional
    public void requestPasswordReset(String email) {
        String normalisedEmail = email.toLowerCase().strip();
        var userOpt = userRepository.findByEmail(normalisedEmail);

        // Always return 204 regardless of whether the email exists. (THR-AUTH-06)
        if (userOpt.isEmpty()) {
            log.debug("Password reset requested for unknown email. Returning 204 silently.");
            return;
        }

        User user = userOpt.get();
        // Delete any existing unused tokens first to prevent token buildup.
        passwordResetTokenRepository.deleteAllByUserId(user.getId());

        String rawToken = UUID.randomUUID().toString();
        String tokenHash = sha256Hex(rawToken);
        Instant expiresAt = Instant.now().plus(Duration.ofHours(1));

        passwordResetTokenRepository.save(
            PasswordResetToken.create(user, tokenHash, expiresAt)
        );

        // STUB: In production, this calls the Notification Service via its REST API.
        // For Phase 3, log the raw token so local testing is possible without an email server.
        log.info("PASSWORD RESET TOKEN (STUB - remove before Phase 6): userId={} token={}",
            user.getId(), rawToken);
    }

    /**
     * Confirms a password reset using the token from the reset email link.
     *
     * @throws PasswordResetTokenInvalidException if the token is invalid, expired, or already used
     */
    @Transactional
    public void confirmPasswordReset(ConfirmPasswordResetRequest request) {
        String tokenHash = sha256Hex(request.token());
        PasswordResetToken resetToken = passwordResetTokenRepository.findByTokenHash(tokenHash)
            .orElseThrow(PasswordResetTokenInvalidException::new);

        if (!resetToken.isValid()) {
            throw new PasswordResetTokenInvalidException();
        }

        // Consume the token first (single-use enforcement).
        resetToken.consume();
        passwordResetTokenRepository.save(resetToken);

        // Update the password.
        User user = resetToken.getUser();
        user.changePasswordHash(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);

        // Revoke all refresh tokens — all existing sessions must re-authenticate.
        refreshTokenRepository.revokeAllByUserId(user.getId(), Instant.now());

        log.info("Password reset confirmed. userId={}", user.getId());
    }

    // ══════════════════════════════════════════════════════════
    // INTERNAL HELPERS
    // ══════════════════════════════════════════════════════════

    /**
     * Issues an access token + refresh token pair for the given user.
     * Both tokens are issued atomically — if the refresh token save fails,
     * no token pair is returned (the transaction rolls back).
     */
    private TokenPair issueTokenPair(User user, String issuedFromIp, String userAgent) {
        // Issue access token (JWT).
        String accessToken = jwtService.issueAccessToken(user.getId(), user.getRole());

        // Issue opaque refresh token.
        String rawRefreshToken = UUID.randomUUID().toString();
        String tokenHash = sha256Hex(rawRefreshToken);
        Instant expiresAt = Instant.now().plusSeconds(
            appProperties.jwt().refreshTokenTtlSeconds()
        );

        RefreshToken refreshToken = RefreshToken.create(user, tokenHash, expiresAt, issuedFromIp, userAgent);
        refreshTokenRepository.save(refreshToken);

        return TokenPair.of(accessToken, rawRefreshToken, appProperties.jwt().accessTokenTtlSeconds());
    }

    /**
     * Computes a SHA-256 hash of the input string and returns it as a lowercase hex string.
     * Used for storing refresh token and password reset token hashes.
     */
    private static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is always available in any standard JRE.
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
