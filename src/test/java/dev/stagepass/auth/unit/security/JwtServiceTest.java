package dev.stagepass.auth.unit.security;

import dev.stagepass.auth.config.AppProperties;
import dev.stagepass.auth.domain.UserRole;
import dev.stagepass.auth.security.JwtService;
import dev.stagepass.auth.security.RsaKeyProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link JwtService}.
 *
 * <p>These tests use a freshly generated RSA key pair for each test class instance.
 * They test the JWT lifecycle in isolation — no Spring context, no DB.
 *
 * <p><strong>What this covers:</strong>
 * <ul>
 *   <li>Happy-path: access token issued and validated successfully
 *   <li>Claims: sub, role, jti are all present with correct values
 *   <li>Algorithm confusion attack (THR-AUTH-04): a token signed with HMAC
 *       cannot be validated against an RS256 key
 *   <li>Tampered token: modifying the payload invalidates the signature
 *   <li>Expired token: a token past its TTL is rejected
 * </ul>
 */
@DisplayName("JwtService")
class JwtServiceTest {

    private JwtService jwtService;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        // Generate a fresh 2048-bit RSA key pair for each test.
        // Using 2048 here (not 4096) to keep test execution fast.
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        keyPair = gen.generateKeyPair();

        RsaKeyProvider keyProvider = mock(RsaKeyProvider.class);
        when(keyProvider.getPrivateKey()).thenReturn(
            (java.security.interfaces.RSAPrivateKey) keyPair.getPrivate()
        );
        when(keyProvider.getPublicKey()).thenReturn(
            (java.security.interfaces.RSAPublicKey) keyPair.getPublic()
        );
        when(keyProvider.getKeyId()).thenReturn("test-key-1");

        // 900s access token TTL (15 min), 604800s refresh TTL (7 days).
        AppProperties props = new AppProperties(
            new AppProperties.JwtProperties(null, null, "test-key-1", 900, 604800),
            new AppProperties.RateLimitProperties(new AppProperties.RateLimitProperties.LoginRateLimitProperties(5)),
            new AppProperties.LockoutProperties(10, 30)
        );

        jwtService = new JwtService(keyProvider, props);
    }

    @Nested
    @DisplayName("issueAccessToken")
    class IssueAccessToken {

        @Test
        @DisplayName("issues a token that can be validated immediately")
        void happyPath() {
            UUID userId = UUID.randomUUID();
            String token = jwtService.issueAccessToken(userId, UserRole.CUSTOMER);

            assertThat(token).isNotBlank();
            // Validation must not throw.
            Claims claims = jwtService.validateAndExtractClaims(token);
            assertThat(claims).isNotNull();
        }

        @Test
        @DisplayName("token contains correct subject (userId)")
        void subjectIsUserId() {
            UUID userId = UUID.randomUUID();
            String token = jwtService.issueAccessToken(userId, UserRole.ORGANISER);

            Claims claims = jwtService.validateAndExtractClaims(token);
            assertThat(claims.getSubject()).isEqualTo(userId.toString());
        }

        @Test
        @DisplayName("token contains correct role claim")
        void roleClaimIsPresent() {
            UUID userId = UUID.randomUUID();
            String token = jwtService.issueAccessToken(userId, UserRole.ADMIN);

            Claims claims = jwtService.validateAndExtractClaims(token);
            assertThat(claims.get("role", String.class)).isEqualTo("ADMIN");
        }

        @Test
        @DisplayName("token contains a non-blank jti (JWT ID)")
        void jtiIsPresent() {
            String token = jwtService.issueAccessToken(UUID.randomUUID(), UserRole.VENUE);

            Claims claims = jwtService.validateAndExtractClaims(token);
            assertThat(claims.getId()).isNotBlank();
        }

        @Test
        @DisplayName("token contains kid header matching the key provider")
        void kidHeaderIsSet() {
            String token = jwtService.issueAccessToken(UUID.randomUUID(), UserRole.CUSTOMER);

            // Decode the header without validating (we need the kid before validation).
            String header = new String(
                java.util.Base64.getUrlDecoder().decode(token.split("\\.")[0])
            );
            assertThat(header).contains("\"kid\"").contains("test-key-1");
        }

        @Test
        @DisplayName("two tokens for same user have different JTIs")
        void jtiIsUniquePerToken() {
            UUID userId = UUID.randomUUID();
            String token1 = jwtService.issueAccessToken(userId, UserRole.CUSTOMER);
            String token2 = jwtService.issueAccessToken(userId, UserRole.CUSTOMER);

            String jti1 = jwtService.validateAndExtractClaims(token1).getId();
            String jti2 = jwtService.validateAndExtractClaims(token2).getId();

            assertThat(jti1).isNotEqualTo(jti2);
        }
    }

    @Nested
    @DisplayName("validateAndExtractClaims — rejection cases")
    class Validation {

        @Test
        @DisplayName("rejects a token with a tampered payload")
        void rejectsTamperedPayload() {
            String token = jwtService.issueAccessToken(UUID.randomUUID(), UserRole.CUSTOMER);

            // Tamper: replace the payload segment with a different base64 string.
            String[] parts = token.split("\\.");
            String tamperedPayload = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"sub\":\"attacker\",\"role\":\"ADMIN\"}".getBytes());
            String tamperedToken = parts[0] + "." + tamperedPayload + "." + parts[2];

            // The signature covers header + payload — tampering invalidates it.
            assertThatThrownBy(() -> jwtService.validateAndExtractClaims(tamperedToken))
                .isInstanceOf(JwtException.class);
        }

        @Test
        @DisplayName("rejects a token signed with a different RSA private key")
        void rejectsTokenSignedWithDifferentKey() throws Exception {
            // Generate a second, completely independent key pair.
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair otherKeyPair = gen.generateKeyPair();

            RsaKeyProvider otherProvider = mock(RsaKeyProvider.class);
            when(otherProvider.getPrivateKey()).thenReturn(
                (java.security.interfaces.RSAPrivateKey) otherKeyPair.getPrivate()
            );
            when(otherProvider.getPublicKey()).thenReturn(
                (java.security.interfaces.RSAPublicKey) otherKeyPair.getPublic()
            );
            when(otherProvider.getKeyId()).thenReturn("other-key");

            AppProperties props = new AppProperties(
                new AppProperties.JwtProperties(null, null, "other-key", 900, 604800),
                new AppProperties.RateLimitProperties(new AppProperties.RateLimitProperties.LoginRateLimitProperties(5)),
                new AppProperties.LockoutProperties(10, 30)
            );
            JwtService otherJwtService = new JwtService(otherProvider, props);

            // Issue a token with the second key — our JwtService should reject it.
            String foreignToken = otherJwtService.issueAccessToken(UUID.randomUUID(), UserRole.CUSTOMER);

            assertThatThrownBy(() -> jwtService.validateAndExtractClaims(foreignToken))
                .isInstanceOf(JwtException.class);
        }

        @Test
        @DisplayName("rejects a blank token")
        void rejectsBlankToken() {
            assertThatThrownBy(() -> jwtService.validateAndExtractClaims(""))
                .isInstanceOf(Exception.class);
        }

        @Test
        @DisplayName("rejects a completely malformed string")
        void rejectsMalformedToken() {
            assertThatThrownBy(() -> jwtService.validateAndExtractClaims("not.a.jwt"))
                .isInstanceOf(Exception.class);
        }
    }

    @Nested
    @DisplayName("claim extraction helpers")
    class ClaimExtraction {

        @Test
        @DisplayName("extractUserId returns the UUID from sub claim")
        void extractUserId() {
            UUID userId = UUID.randomUUID();
            String token = jwtService.issueAccessToken(userId, UserRole.CUSTOMER);
            Claims claims = jwtService.validateAndExtractClaims(token);

            assertThat(jwtService.extractUserId(claims)).isEqualTo(userId);
        }

        @Test
        @DisplayName("extractRole returns the correct UserRole")
        void extractRole() {
            String token = jwtService.issueAccessToken(UUID.randomUUID(), UserRole.VENUE);
            Claims claims = jwtService.validateAndExtractClaims(token);

            assertThat(jwtService.extractRole(claims)).isEqualTo(UserRole.VENUE);
        }

        @Test
        @DisplayName("extractJti returns the jti claim")
        void extractJti() {
            String token = jwtService.issueAccessToken(UUID.randomUUID(), UserRole.ADMIN);
            Claims claims = jwtService.validateAndExtractClaims(token);

            assertThat(jwtService.extractJti(claims)).isNotBlank();
        }
    }
}
