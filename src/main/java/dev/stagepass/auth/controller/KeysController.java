package dev.stagepass.auth.controller;

import dev.stagepass.auth.security.JwksService;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Exposes the JSON Web Key Set (JWKS) endpoint.
 *
 * <p>All services validate JWTs locally using the public key fetched from this endpoint.
 * No service calls the Auth Service per request — they cache the JWKS and validate
 * the RS256 signature locally. (ADR-003: local JWT validation model)
 *
 * <p><strong>Why a long cache TTL here?</strong>
 * Key rotation (Phase 9 with Vault dynamic secrets) is rare — typically hours to days.
 * A 1-hour max-age means dependent services may have a stale key for up to 1 hour
 * after rotation. For Phase 3–8 with a static key pair, this is acceptable.
 * When key rotation is introduced, the transition period (serving both old + new key
 * in the JWKS simultaneously) covers the cache window. (THR-AUTH-01)
 *
 * <p><strong>Content type:</strong>
 * RFC 7517 recommends {@code application/json} for JWKS.
 * Some clients check for {@code application/jwk-set+json} — both are returned.
 */
@RestController
@RequestMapping("/auth")
public class KeysController {

    private final JwksService jwksService;

    public KeysController(JwksService jwksService) {
        this.jwksService = jwksService;
    }

    /**
     * GET /auth/jwks
     *
     * <p>Returns the JWKS document containing the RSA public key used to verify
     * access tokens. The {@code kid} in the JWKS matches the {@code kid} header
     * in issued JWTs, allowing clients to select the correct key when multiple
     * keys are present (key rotation support).
     *
     * <p>Permitted without authentication — downstream services must be able to
     * fetch the JWKS on startup before they have any tokens.
     */
    @GetMapping(
        value = "/jwks",
        produces = {MediaType.APPLICATION_JSON_VALUE, "application/jwk-set+json"}
    )
    public ResponseEntity<Map<String, Object>> getJwks() {
        return ResponseEntity.ok()
            // 1 hour client cache. On key rotation, the transition period in JwksService
            // (serving both old and new key) ensures stale caches still validate in-flight tokens.
            .cacheControl(CacheControl.maxAge(1, TimeUnit.HOURS).mustRevalidate())
            .contentType(MediaType.APPLICATION_JSON)
            .body(jwksService.buildJwksResponse());
    }
}
