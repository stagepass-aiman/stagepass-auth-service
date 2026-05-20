package dev.stagepass.auth.security;

import dev.stagepass.auth.config.AppProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Per-IP rate limiter for the login endpoint.
 *
 * <p>Implements a fixed-window counter using Redis INCR + EXPIRE.
 * The window is 60 seconds. If the counter exceeds the configured limit
 * within the window, the request is rejected with a 429.
 *
 * <p><strong>Limit:</strong> configurable via {@code app.rate-limit.login.requests-per-minute}.
 * Default: 5 req/min per IP. (THR-AUTH-08)
 *
 * <p><strong>Algorithm:</strong>
 * <pre>
 *   key = auth:rate:login:<ip>
 *   count = INCR key
 *   if count == 1: EXPIRE key 60           // Start window on first request
 *   if count > limit: reject 429
 * </pre>
 *
 * <p><strong>Limitation:</strong> fixed-window (not sliding). A client can make
 * 5 requests at second 59 and 5 more at second 61, for an effective burst of 10.
 * This is acceptable for Phase 3; a sliding window (Bucket4j + Redis) can be
 * introduced in Phase 7 if the burst vulnerability is a concern at load.
 *
 * <p><strong>Key structure:</strong> {@code auth:rate:login:<ip>}
 */
@Component
public class LoginRateLimiter {

    private static final Logger log = LoggerFactory.getLogger(LoginRateLimiter.class);
    private static final String KEY_PREFIX = "auth:rate:login:";
    private static final Duration WINDOW = Duration.ofSeconds(60);

    private final StringRedisTemplate redisTemplate;
    private final int requestsPerMinute;

    public LoginRateLimiter(StringRedisTemplate redisTemplate, AppProperties properties) {
        this.redisTemplate = redisTemplate;
        this.requestsPerMinute = properties.rateLimit().login().requestsPerMinute();
    }

    /**
     * Checks and increments the rate limit counter for the given IP.
     *
     * @param ip the client IP address (from X-Forwarded-For or remote addr)
     * @return true if the request is within the rate limit, false if it should be rejected
     */
    public boolean isAllowed(String ip) {
        String key = KEY_PREFIX + ip;

        // INCR is atomic — no race condition between increment and check.
        Long count = redisTemplate.opsForValue().increment(key);

        if (count == null) {
            // Redis error — fail open to avoid blocking legitimate logins.
            // Log a warning so the observability layer can alert. (NFR-OBS-002)
            log.warn("Redis rate limiter returned null for key={}. Failing open.", key);
            return true;
        }

        if (count == 1L) {
            // First request in this window — set expiry.
            // EXPIRE is set after INCR, not in the same command.
            // There is a tiny race if Redis crashes between INCR and EXPIRE,
            // but the practical impact is a key without expiry (eventually bounded
            // by Redis maxmemory policy). Acceptable for Phase 3.
            redisTemplate.expire(key, WINDOW);
        }

        boolean allowed = count <= requestsPerMinute;
        if (!allowed) {
            log.warn("Login rate limit exceeded. ip={} count={} limit={}", ip, count, requestsPerMinute);
        }
        return allowed;
    }
}
