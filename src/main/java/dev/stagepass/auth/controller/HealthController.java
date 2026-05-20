package dev.stagepass.auth.controller;

import dev.stagepass.auth.security.JwksService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Health check endpoints for Kubernetes probes.
 *
 * <p>Two endpoints with distinct semantics (NFR-OBS, Section 11 conventions):
 *
 * <ul>
 *   <li><strong>GET /health/live</strong> — Liveness probe.
 *       Is the process alive and not deadlocked?
 *       Kubernetes restarts the pod if this returns non-2xx.
 *       Should NEVER check external dependencies — a DB outage should not
 *       cause pod restarts. This endpoint just returns 200.
 *
 *   <li><strong>GET /health/ready</strong> — Readiness probe.
 *       Is the service ready to handle traffic?
 *       Kubernetes removes the pod from the load balancer if this returns non-2xx.
 *       Must verify: PostgreSQL connectivity, Redis connectivity, RSA key loaded.
 *       An external dependency failure → 503 Service Unavailable.
 * </ul>
 *
 * <p>These endpoints are explicitly permitted without authentication in
 * {@link dev.stagepass.auth.config.SecurityConfig} so Kubernetes probes
 * can reach them without credentials.
 *
 * <p><strong>Why not Spring Actuator?</strong>
 * Spring Actuator's /actuator/health provides health checks but requires
 * additional config to expose it without authentication and to separate
 * liveness from readiness. Rolling our own gives us full control over the
 * response body shape and avoids exposing Actuator's other sensitive endpoints.
 */
@RestController
@RequestMapping("/health")
public class HealthController {

    private static final Logger log = LoggerFactory.getLogger(HealthController.class);

    private final JdbcTemplate jdbcTemplate;
    private final StringRedisTemplate redisTemplate;
    private final JwksService jwksService;

    public HealthController(JdbcTemplate jdbcTemplate,
                            StringRedisTemplate redisTemplate,
                            JwksService jwksService) {
        this.jdbcTemplate = jdbcTemplate;
        this.redisTemplate = redisTemplate;
        this.jwksService = jwksService;
    }

    /**
     * GET /health/live
     *
     * <p>Liveness check — is the JVM process alive?
     * Always returns 200 if the application context is up.
     * Does NOT check external dependencies.
     */
    @GetMapping("/live")
    public ResponseEntity<Map<String, String>> liveness() {
        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "service", "stagepass-auth-service",
            "timestamp", Instant.now().toString()
        ));
    }

    /**
     * GET /health/ready
     *
     * <p>Readiness check — can the service handle traffic?
     * Checks PostgreSQL, Redis, and RSA key availability.
     * Returns 503 if any dependency is unavailable.
     *
     * <p>The response body includes per-component status so it is useful
     * for debugging without requiring access to internal logs.
     */
    @GetMapping("/ready")
    public ResponseEntity<Map<String, Object>> readiness() {
        // Use LinkedHashMap to preserve insertion order in JSON output.
        Map<String, Object> checks = new LinkedHashMap<>();
        boolean allUp = true;

        // ── PostgreSQL ──────────────────────────────────────────
        try {
            jdbcTemplate.queryForObject("SELECT 1", Integer.class);
            checks.put("postgresql", "UP");
        } catch (Exception ex) {
            log.error("Readiness check: PostgreSQL unavailable. error={}", ex.getMessage());
            checks.put("postgresql", "DOWN");
            allUp = false;
        }

        // ── Redis ───────────────────────────────────────────────
        try {
            String pong = redisTemplate.getConnectionFactory()
                .getConnection()
                .ping();
            checks.put("redis", "PONG".equals(pong) ? "UP" : "DOWN");
            if (!"PONG".equals(pong)) {
                log.warn("Readiness check: Redis returned unexpected ping response. response={}", pong);
                allUp = false;
            }
        } catch (Exception ex) {
            log.error("Readiness check: Redis unavailable. error={}", ex.getMessage());
            checks.put("redis", "DOWN");
            allUp = false;
        }

        // ── RSA Key ─────────────────────────────────────────────
        // If the key is not loaded, we cannot issue or verify any JWT.
        // The service should not serve traffic in this state.
        boolean keyLoaded = jwksService.isKeyLoaded();
        checks.put("rsaKey", keyLoaded ? "LOADED" : "MISSING");
        if (!keyLoaded) {
            log.error("Readiness check: RSA key not loaded. Service cannot issue JWTs.");
            allUp = false;
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", allUp ? "UP" : "DOWN");
        body.put("service", "stagepass-auth-service");
        body.put("timestamp", Instant.now().toString());
        body.put("checks", checks);

        return allUp
            ? ResponseEntity.ok(body)
            : ResponseEntity.status(503).body(body);
    }
}
