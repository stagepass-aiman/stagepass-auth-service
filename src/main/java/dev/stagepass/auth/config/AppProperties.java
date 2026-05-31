package dev.stagepass.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Type-safe configuration binding for the {@code app.*} namespace in application.yml.
 *
 * <p>Java 21 records give us immutable, compact property holders.
 * No @Data, no @Getter — records have accessor methods by default.
 *
 * <p>Validated by {@code @EnableConfigurationProperties} in JwtConfig.
 * If a required property is missing (e.g. AUTH_RSA_PRIVATE_KEY), the
 * application fails to start — fail-fast at boot, not at runtime.
 */
@ConfigurationProperties(prefix = "app")
public record AppProperties(
    JwtProperties jwt,
    RateLimitProperties rateLimit,
    LockoutProperties lockout
) {

    public record JwtProperties(
        String privateKey,
        String publicKey,
        @DefaultValue("stagepass-auth-key-1") String keyId,
        // iss claim value — RFC 7519 §4.1.1. Identifies THIS auth server as the
        // minting authority. Option A: a per-environment issuer URI, so a token
        // minted in staging is distinguishable from one minted in prod even when
        // they share a signing key. Default is the local-dev issuer; staging/prod
        // override via the AUTH_JWT_ISSUER env var (12-factor — never hardcoded).
        @DefaultValue("http://localhost:8081") String issuer,
        @DefaultValue("900") int accessTokenTtlSeconds,
        @DefaultValue("604800") int refreshTokenTtlSeconds
    ) {}

    public record RateLimitProperties(LoginRateLimitProperties login) {
        public record LoginRateLimitProperties(
            @DefaultValue("5") int requestsPerMinute
        ) {}
    }

    public record LockoutProperties(
        @DefaultValue("10") int maxAttempts,
        @DefaultValue("30") int durationMinutes
    ) {}
}
