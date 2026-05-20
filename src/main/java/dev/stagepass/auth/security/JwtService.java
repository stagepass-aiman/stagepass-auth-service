package dev.stagepass.auth.security;

import dev.stagepass.auth.config.AppProperties;
import dev.stagepass.auth.domain.UserRole;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * Handles RS256 JWT issuance and validation for access tokens.
 *
 * <p><strong>Claim structure (NFR-SEC-001, ADR-003 §3.2.2):</strong>
 * <ul>
 *   <li>{@code sub} — userId (UUID string)</li>
 *   <li>{@code role} — platform role (CUSTOMER | ORGANISER | VENUE | ADMIN)</li>
 *   <li>{@code jti} — JWT ID (UUID) — used for targeted JTI blocklist revocation</li>
 *   <li>{@code iat} — issued-at (epoch seconds)</li>
 *   <li>{@code exp} — expiry (epoch seconds, ≤ 15 min from iat)</li>
 *   <li>{@code kid} — key ID in header (matches JWKS kid field)</li>
 * </ul>
 *
 * <p><strong>Algorithm: RS256.</strong> Private key signs; public key verifies.
 * The public key is published at /auth/jwks so downstream services can
 * validate tokens locally without calling Auth Service per request.
 * (Anti-pattern avoided: no per-request Auth Service call)
 *
 * <p><strong>Algorithm confusion attack prevention (THR-AUTH-04):</strong>
 * JJWT 0.12.x explicitly requires specifying the expected algorithm on parse.
 * The {@code verifyWith()} call pins the algorithm to RS256 — a token with
 * {@code alg: none} or {@code alg: HS256} will be rejected by JJWT before
 * our code sees the claims.
 */
@Component
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);

    /** Custom claim name for the platform role. */
    public static final String CLAIM_ROLE = "role";

    private final RsaKeyProvider rsaKeyProvider;
    private final int accessTokenTtlSeconds;

    public JwtService(RsaKeyProvider rsaKeyProvider, AppProperties properties) {
        this.rsaKeyProvider = rsaKeyProvider;
        this.accessTokenTtlSeconds = properties.jwt().accessTokenTtlSeconds();

        // Validate the configured TTL at startup. Fail fast if misconfigured.
        if (accessTokenTtlSeconds > 900) {
            throw new IllegalStateException(
                "Access token TTL (" + accessTokenTtlSeconds + "s) exceeds the maximum " +
                "allowed 900s (15 minutes). NFR-SEC-002 violation. " +
                "Set JWT_ACCESS_TTL ≤ 900 in environment configuration."
            );
        }
        log.info("JwtService initialised. access_token_ttl={}s", accessTokenTtlSeconds);
    }

    /**
     * Issues a new RS256-signed access token.
     *
     * @param userId   the user's UUID (becomes the {@code sub} claim)
     * @param role     the user's platform role (custom {@code role} claim)
     * @return         the signed JWT string
     */
    public String issueAccessToken(UUID userId, UserRole role) {
        var now = Instant.now();
        var expiry = now.plusSeconds(accessTokenTtlSeconds);
        var jti = UUID.randomUUID().toString();

        return Jwts.builder()
            // Header — kid allows downstream services to select the correct
            // JWKS key when multiple keys are in rotation.
            .header()
                .keyId(rsaKeyProvider.getKeyId())
                .and()
            // Registered claims
            .subject(userId.toString())
            .id(jti)                               // jti — JWT ID for revocation
            .issuedAt(Date.from(now))
            .expiration(Date.from(expiry))
            // Custom claim — platform role
            .claim(CLAIM_ROLE, role.name())
            // Sign with RS256 using the private key
            .signWith(rsaKeyProvider.getPrivateKey(), Jwts.SIG.RS256)
            .compact();
    }

    /**
     * Validates a JWT string and returns its claims.
     *
     * <p>Validation steps performed by JJWT:
     * <ol>
     *   <li>Algorithm verification — rejects non-RS256 tokens (THR-AUTH-04)</li>
     *   <li>Signature verification using the RSA public key</li>
     *   <li>Expiry check ({@code exp} claim must be in the future)</li>
     *   <li>Not-before check ({@code nbf} if present)</li>
     * </ol>
     *
     * <p>JTI blocklist checking is NOT done here — it is done by
     * {@link JtiBlocklistService} in the filter layer. Separating these
     * concerns keeps JwtService pure (no Redis dependency) and testable.
     *
     * @param token the JWT string from the Authorization header
     * @return parsed claims if valid
     * @throws JwtException if the token is invalid, expired, or malformed
     */
    public Claims validateAndExtractClaims(String token) {
        return Jwts.parser()
            // PIN the algorithm — prevents algorithm confusion (THR-AUTH-04).
            // A token with alg:none or alg:HS256 will be rejected before claims are read.
            .verifyWith(rsaKeyProvider.getPublicKey())
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }

    /**
     * Returns the remaining lifetime of a token in seconds (for JTI blocklist TTL).
     * Returns 0 if the token has already expired.
     */
    public long getRemainingTtlSeconds(Claims claims) {
        var expiry = claims.getExpiration().toInstant();
        var now = Instant.now();
        return Math.max(0L, expiry.getEpochSecond() - now.getEpochSecond());
    }

    /**
     * Extracts the userId from validated claims.
     *
     * @throws IllegalArgumentException if sub is not a valid UUID
     */
    public UUID extractUserId(Claims claims) {
        return UUID.fromString(claims.getSubject());
    }

    /**
     * Extracts the platform role from validated claims.
     *
     * @throws IllegalArgumentException if role claim is missing or invalid
     */
    public UserRole extractRole(Claims claims) {
        String roleName = claims.get(CLAIM_ROLE, String.class);
        if (roleName == null) {
            throw new IllegalArgumentException("JWT missing 'role' claim");
        }
        return UserRole.valueOf(roleName);
    }

    public int getAccessTokenTtlSeconds() { return accessTokenTtlSeconds; }

    /**
     * Extracts the jti claim for JTI blocklist operations.
     *
     * @throws IllegalArgumentException if jti is missing
     */
    public String extractJti(Claims claims) {
        String jti = claims.getId();
        if (jti == null) {
            throw new IllegalArgumentException("JWT missing 'jti' claim");
        }
        return jti;
    }
}
