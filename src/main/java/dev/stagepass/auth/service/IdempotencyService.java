package dev.stagepass.auth.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Optional;

/**
 * Redis-backed idempotency cache.
 *
 * <p>Callers supply an idempotency key (from the {@code Idempotency-Key} request header).
 * On the first request, the response is computed and stored in Redis.
 * On duplicate requests with the same key, the cached response is returned immediately.
 *
 * <p><strong>Key structure:</strong> {@code auth:idem:<idempotency-key>}
 * <strong>TTL:</strong> 24 hours (fixed, regardless of when in that window the key was first used).
 *
 * <p>The value is JSON-serialised — generic across all response types.
 * Deserialisation uses the caller-supplied {@link Class} for type safety.
 *
 * <p><strong>Scope:</strong> used for POST /auth/register and POST /auth/login
 * to make client retries safe during network partitions.
 * NOT used for POST /auth/refresh (tokens are inherently idempotent by rotation).
 */
@Service
public class IdempotencyService {

    private static final Logger log = LoggerFactory.getLogger(IdempotencyService.class);
    private static final String KEY_PREFIX = "auth:idem:";
    private static final Duration TTL = Duration.ofHours(24);

    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    public IdempotencyService(StringRedisTemplate redisTemplate, ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
    }

    /**
     * Retrieves a cached response for the given idempotency key.
     *
     * @param idempotencyKey the client-supplied key
     * @param responseType   the expected response class for deserialisation
     * @param <T>            response type
     * @return the cached response, or empty if this is a new request
     */
    public <T> Optional<T> get(String idempotencyKey, Class<T> responseType) {
        if (idempotencyKey == null || idempotencyKey.isBlank()) {
            return Optional.empty();
        }

        String key = KEY_PREFIX + idempotencyKey;
        try {
            String cached = redisTemplate.opsForValue().get(key);
            if (cached != null) {
                log.debug("Idempotency cache hit. key={}", idempotencyKey);
                return Optional.of(objectMapper.readValue(cached, responseType));
            }
        } catch (JsonProcessingException e) {
            // Cached value is unparseable — treat as cache miss and recompute.
            log.warn("Failed to deserialise cached idempotency response. key={}", idempotencyKey, e);
        } catch (Exception e) {
            // Redis unavailable — fail open (compute fresh response).
            log.warn("Idempotency cache read failed. key={} Failing open.", idempotencyKey, e);
        }

        return Optional.empty();
    }

    /**
     * Stores a response under the given idempotency key for 24 hours.
     *
     * @param idempotencyKey the client-supplied key
     * @param response       the response to cache
     */
    public void put(String idempotencyKey, Object response) {
        if (idempotencyKey == null || idempotencyKey.isBlank()) {
            return;
        }

        String key = KEY_PREFIX + idempotencyKey;
        try {
            String serialised = objectMapper.writeValueAsString(response);
            redisTemplate.opsForValue().set(key, serialised, TTL);
            log.debug("Idempotency response cached. key={} ttl=24h", idempotencyKey);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialise response for idempotency cache. key={}", idempotencyKey, e);
        } catch (Exception e) {
            // Redis write failure — non-fatal. Client will get a fresh (correct) response,
            // and the next duplicate request will recompute. Idempotency cache is best-effort.
            log.warn("Idempotency cache write failed. key={}", idempotencyKey, e);
        }
    }
}
