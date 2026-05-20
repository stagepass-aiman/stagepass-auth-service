package dev.stagepass.auth.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Manages the JWT JTI (JWT ID) blocklist in Redis.
 *
 * <p>When a user logs out, or an access token is revoked, its JTI is added
 * to this blocklist with a TTL equal to the token's remaining lifetime.
 * Once the token would have expired anyway, the blocklist entry is also expired —
 * Redis automatically removes it. This keeps the blocklist bounded.
 * (Mitigates THR-AUTH-09: Redis JTI blocklist memory growth)
 *
 * <p><strong>Key structure:</strong>
 * {@code auth:jti:<jti>} → value {@code "1"}, TTL = remaining token lifetime seconds.
 *
 * <p><strong>Redis command used:</strong>
 * {@code SET auth:jti:<jti> 1 EX <remaining_seconds>} — atomic single command.
 * No separate EXPIRE call needed; SET EX is atomic.
 *
 * <p><strong>Check path:</strong> {@link BearerTokenFilter} calls {@link #isRevoked(String)}
 * on every request that carries a JWT. This is a single Redis GET — typically < 1ms.
 *
 * <p><strong>Key prefix:</strong> all auth service Redis keys use {@code auth:} prefix.
 * This allows other services to share Redis DB 0 without key collisions, though
 * in production each service should have its own Redis instance.
 */
@Component
public class JtiBlocklistService {

    private static final Logger log = LoggerFactory.getLogger(JtiBlocklistService.class);

    /** Prefix for all JTI blocklist entries. */
    private static final String KEY_PREFIX = "auth:jti:";

    private final StringRedisTemplate redisTemplate;

    public JtiBlocklistService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * Adds a JTI to the blocklist.
     *
     * <p>TTL is set to the remaining token lifetime, not the full token TTL.
     * If a token has 5 minutes left, the blocklist entry lives for 5 minutes.
     * Once the token is expired, the blocklist entry expires too — Redis
     * does not accumulate stale blocklist entries. (THR-AUTH-09)
     *
     * @param jti                 the JWT ID claim value
     * @param remainingTtlSeconds seconds until the token expires; must be > 0
     */
    public void revoke(String jti, long remainingTtlSeconds) {
        if (remainingTtlSeconds <= 0) {
            // Token is already expired — no need to blocklist it.
            // An expired token is rejected by JwtService.validateAndExtractClaims() anyway.
            log.debug("Skipping blocklist entry for already-expired JTI. jti={}", jti);
            return;
        }

        String key = KEY_PREFIX + jti;
        redisTemplate.opsForValue().set(key, "1", Duration.ofSeconds(remainingTtlSeconds));
        log.debug("JTI revoked. jti={} ttl_seconds={}", jti, remainingTtlSeconds);
    }

    /**
     * Returns true if the given JTI is in the blocklist (i.e. the token has been revoked).
     *
     * <p>This is called on every authenticated request in {@link BearerTokenFilter}.
     * The implementation is a single Redis GET — O(1), typically < 1ms.
     *
     * @param jti the JWT ID claim value
     * @return true if revoked, false if active or key expired
     */
    public boolean isRevoked(String jti) {
        String key = KEY_PREFIX + jti;
        Boolean exists = redisTemplate.hasKey(key);
        return Boolean.TRUE.equals(exists);
    }
}
