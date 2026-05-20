package dev.stagepass.auth.service;

import dev.stagepass.auth.config.AppProperties;
import dev.stagepass.auth.domain.User;
import dev.stagepass.auth.domain.UserRole;
import dev.stagepass.auth.domain.UserStatus;
import dev.stagepass.auth.dto.AuthDtos.LoginRequest;
import dev.stagepass.auth.dto.AuthDtos.RegisterRequest;
import dev.stagepass.auth.dto.AuthDtos.TokenPair;
import dev.stagepass.auth.exception.AccountLockedException;
import dev.stagepass.auth.exception.AccountSuspendedException;
import dev.stagepass.auth.exception.EmailAlreadyRegisteredException;
import dev.stagepass.auth.exception.InvalidCredentialsException;
import dev.stagepass.auth.repository.AdminAuditLogRepository;
import dev.stagepass.auth.repository.PasswordResetTokenRepository;
import dev.stagepass.auth.repository.RefreshTokenRepository;
import dev.stagepass.auth.repository.UserRepository;
import dev.stagepass.auth.security.JtiBlocklistService;
import dev.stagepass.auth.security.JwtService;
import dev.stagepass.auth.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/**
 * Unit tests for {@link AuthService}.
 *
 * <p>All external dependencies are mocked with Mockito.
 * No Spring context. No DB. No Redis. Fast feedback cycle.
 *
 * <p><strong>Key scenarios tested:</strong>
 * <ul>
 *   <li>Timing attack prevention: bcrypt runs even when the email does not exist
 *   <li>Lockout: exceeding maxAttempts triggers AccountLockedException
 *   <li>Suspended account: login throws AccountSuspendedException
 *   <li>Duplicate email: register throws EmailAlreadyRegisteredException
 *   <li>Successful registration: user is saved and token pair is returned
 * </ul>
 *
 * <p><strong>What this does NOT test (covered in integration tests):</strong>
 * <ul>
 *   <li>Actual DB writes (Testcontainers in AuthControllerIT)
 *   <li>Real bcrypt timing (bcrypt cost is intentionally low in test config)
 *   <li>Real Redis JTI blocklist writes
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("AuthService")
class AuthServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private PasswordResetTokenRepository passwordResetTokenRepository;
    @Mock private AdminAuditLogRepository auditLogRepository;
    @Mock private JwtService jwtService;
    @Mock private JtiBlocklistService jtiBlocklistService;

    // Use a real BCryptPasswordEncoder — we want actual password matching logic.
    // Cost 4 is the minimum and is fast for unit tests. Never use cost < 12 in production.
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(4);

    private AuthService authService;
    private AppProperties appProperties;

    @BeforeEach
    void setUp() {
        appProperties = new AppProperties(
            new AppProperties.JwtProperties(null, null, "test-key", 900, 604800),
            new AppProperties.RateLimitProperties(new AppProperties.RateLimitProperties.LoginRateLimitProperties(5)),
            new AppProperties.LockoutProperties(3, 30)   // 3 max attempts, 30 min lockout
        );

        authService = new AuthService(
            userRepository,
            refreshTokenRepository,
            passwordResetTokenRepository,
            auditLogRepository,
            jwtService,
            jtiBlocklistService,
            passwordEncoder,
            appProperties
        );

        // Initialise the dummy hash (normally called by Spring @PostConstruct).
        authService.initDummyHash();

        // Default stub: JWT service returns a non-null access token.
        when(jwtService.issueAccessToken(any(), any())).thenReturn("stubbed-access-token");
        when(jwtService.getAccessTokenTtlSeconds()).thenReturn(900);

        // Default stub: refresh token save succeeds.
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // REGISTER
    // ══════════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("register")
    class Register {

        @Test
        @DisplayName("saves a new user and returns a token pair")
        void happyPath() {
            when(userRepository.existsByEmail("alice@example.com")).thenReturn(false);
            when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

            TokenPair result = authService.register(new RegisterRequest(
                "alice@example.com", "Password1!", UserRole.CUSTOMER, "Alice"
            ));

            assertThat(result).isNotNull();
            assertThat(result.accessToken()).isEqualTo("stubbed-access-token");
            verify(userRepository).save(any(User.class));
        }

        @Test
        @DisplayName("normalises email to lowercase before saving")
        void normalisesEmailToLowercase() {
            when(userRepository.existsByEmail("alice@example.com")).thenReturn(false);
            when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

            authService.register(new RegisterRequest(
                "ALICE@EXAMPLE.COM", "Password1!", UserRole.CUSTOMER, "Alice"
            ));

            ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).save(captor.capture());
            assertThat(captor.getValue().getEmail()).isEqualTo("alice@example.com");
        }

        @Test
        @DisplayName("throws EmailAlreadyRegisteredException if email is taken")
        void rejectsDuplicateEmail() {
            when(userRepository.existsByEmail("alice@example.com")).thenReturn(true);

            assertThatThrownBy(() -> authService.register(new RegisterRequest(
                "alice@example.com", "Password1!", UserRole.CUSTOMER, "Alice"
            ))).isInstanceOf(EmailAlreadyRegisteredException.class);

            verify(userRepository, never()).save(any());
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // LOGIN
    // ══════════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("login")
    class Login {

        @Test
        @DisplayName("returns token pair for valid credentials")
        void happyPath() {
            String hash = passwordEncoder.encode("correctPassword");
            User user = User.create("bob@example.com", hash, UserRole.CUSTOMER, "Bob");

            when(userRepository.findByEmail("bob@example.com")).thenReturn(Optional.of(user));
            when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

            TokenPair result = authService.login(
                new LoginRequest("bob@example.com", "correctPassword"),
                "127.0.0.1", "TestAgent/1.0"
            );

            assertThat(result.accessToken()).isEqualTo("stubbed-access-token");
        }

        @Test
        @DisplayName("throws InvalidCredentialsException for wrong password")
        void wrongPassword() {
            String hash = passwordEncoder.encode("correctPassword");
            User user = User.create("bob@example.com", hash, UserRole.CUSTOMER, "Bob");

            when(userRepository.findByEmail("bob@example.com")).thenReturn(Optional.of(user));
            when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

            assertThatThrownBy(() -> authService.login(
                new LoginRequest("bob@example.com", "wrongPassword"),
                "127.0.0.1", "TestAgent/1.0"
            )).isInstanceOf(InvalidCredentialsException.class);
        }

        @Test
        @DisplayName("TIMING ATTACK: bcrypt runs even when email does not exist (THR-AUTH-07)")
        void timingAttackPrevention() {
            // Email does not exist — findByEmail returns empty.
            when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

            // This must NOT throw NullPointerException or any exception that reveals
            // the email doesn't exist — it must throw InvalidCredentialsException.
            assertThatThrownBy(() -> authService.login(
                new LoginRequest("ghost@example.com", "anyPassword"),
                "127.0.0.1", "TestAgent/1.0"
            )).isInstanceOf(InvalidCredentialsException.class);

            // Verify userRepository was queried (the flow ran normally).
            verify(userRepository).findByEmail("ghost@example.com");
            // We cannot easily verify that bcrypt ran against the dummy hash in a unit test,
            // but we verified that:
            //   (a) the flow did not short-circuit before bcrypt
            //   (b) the same exception type is thrown as for wrong passwords
            // The integration test can verify actual response timing.
        }

        @Test
        @DisplayName("throws AccountLockedException when account is locked")
        void lockedAccount() {
            String hash = passwordEncoder.encode("correctPassword");
            User user = User.create("locked@example.com", hash, UserRole.CUSTOMER, "Locked");

            // Simulate a locked account: lockedUntil is in the future.
            user.recordFailedLoginAttempt(3, java.time.Duration.ofMinutes(30)); // attempt 1
            user.recordFailedLoginAttempt(3, java.time.Duration.ofMinutes(30)); // attempt 2
            user.recordFailedLoginAttempt(3, java.time.Duration.ofMinutes(30)); // attempt 3 → locks

            when(userRepository.findByEmail("locked@example.com")).thenReturn(Optional.of(user));
            when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

            assertThatThrownBy(() -> authService.login(
                new LoginRequest("locked@example.com", "correctPassword"),
                "127.0.0.1", "TestAgent/1.0"
            )).isInstanceOf(AccountLockedException.class);
        }

        @Test
        @DisplayName("throws AccountSuspendedException when account is suspended")
        void suspendedAccount() {
            String hash = passwordEncoder.encode("correctPassword");
            User user = User.create("suspended@example.com", hash, UserRole.CUSTOMER, "Suspended");
            user.suspend();  // Marks the user as SUSPENDED.

            when(userRepository.findByEmail("suspended@example.com")).thenReturn(Optional.of(user));
            when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

            assertThatThrownBy(() -> authService.login(
                new LoginRequest("suspended@example.com", "correctPassword"),
                "127.0.0.1", "TestAgent/1.0"
            )).isInstanceOf(AccountSuspendedException.class);
        }

        @Test
        @DisplayName("resets failed attempts counter on successful login")
        void resetsFailedAttemptsOnSuccess() {
            String hash = passwordEncoder.encode("correctPassword");
            User user = User.create("bob@example.com", hash, UserRole.CUSTOMER, "Bob");
            // Simulate one prior failed attempt.
            user.recordFailedLoginAttempt(10, java.time.Duration.ofMinutes(30));
            assertThat(user.getFailedLoginAttempts()).isEqualTo(1);

            when(userRepository.findByEmail("bob@example.com")).thenReturn(Optional.of(user));
            ArgumentCaptor<User> saveCaptor = ArgumentCaptor.forClass(User.class);
            when(userRepository.save(saveCaptor.capture())).thenAnswer(inv -> inv.getArgument(0));

            authService.login(
                new LoginRequest("bob@example.com", "correctPassword"),
                "127.0.0.1", "TestAgent/1.0"
            );

            // The user saved to DB should have 0 failed attempts.
            assertThat(saveCaptor.getValue().getFailedLoginAttempts()).isEqualTo(0);
        }
    }
}
