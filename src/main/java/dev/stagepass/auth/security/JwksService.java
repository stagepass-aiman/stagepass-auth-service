package dev.stagepass.auth.security;

import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Builds the JWKS (JSON Web Key Set) response from the RSA public key.
 *
 * <p>The JWKS endpoint (GET /auth/jwks) allows downstream services to fetch
 * the public key at startup and cache it for local JWT validation. This is
 * the architecture pattern that eliminates per-request Auth Service calls.
 * (ADR-003 §3.2.2)
 *
 * <p>JWKS construction is pure Java — no nimbus dependency.
 * An RSA JWK requires: kty, use, n (modulus), e (exponent), kid, alg.
 * These are extracted directly from the {@link java.security.interfaces.RSAPublicKey}.
 *
 * <p>Response must include {@code Cache-Control: max-age=3600} so downstream
 * services cache the JWKS for 1 hour and only re-fetch on 401 (key rotation).
 */
@Component
public class JwksService {

    private final RsaKeyProvider rsaKeyProvider;

    public JwksService(RsaKeyProvider rsaKeyProvider) {
        this.rsaKeyProvider = rsaKeyProvider;
    }

    /**
     * Builds the JWKS response body.
     *
     * <p>The returned map serialises to:
     * <pre>
     * {
     *   "keys": [{
     *     "kty": "RSA",
     *     "use": "sig",
     *     "alg": "RS256",
     *     "kid": "stagepass-auth-key-1",
     *     "n": "<base64url-modulus>",
     *     "e": "<base64url-exponent>"
     *   }]
     * }
     * </pre>
     */
    public Map<String, Object> buildJwksResponse() {
        RSAPublicKey publicKey = rsaKeyProvider.getPublicKey();

        // Base64URL-encode the RSA public key components (RFC 7517).
        // BigInteger.toByteArray() may include a leading 0x00 byte for sign;
        // strip it to get the canonical unsigned representation.
        String n = base64UrlEncode(publicKey.getModulus());
        String e = base64UrlEncode(publicKey.getPublicExponent());

        Map<String, String> jwk = Map.of(
            "kty", "RSA",            // Key type
            "use", "sig",            // Public key use: signature verification
            "alg", "RS256",          // Algorithm
            "kid", rsaKeyProvider.getKeyId(),  // Key ID — matches JWT header kid
            "n", n,                  // RSA modulus (Base64URL, unsigned)
            "e", e                   // RSA public exponent (Base64URL)
        );

        return Map.of("keys", List.of(jwk));
    }

    /** Returns true if the RSA public key is loaded and ready for JWKS publication. */
    public boolean isKeyLoaded() {
        try {
            rsaKeyProvider.getPublicKey();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Base64URL-encodes a BigInteger as an unsigned byte array (no leading sign byte).
     * RFC 7517 requires Base64URL without padding.
     */
    private static String base64UrlEncode(BigInteger value) {
        byte[] bytes = value.toByteArray();
        // Remove leading 0x00 sign byte that BigInteger may include.
        if (bytes[0] == 0) {
            byte[] stripped = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, stripped, 0, stripped.length);
            bytes = stripped;
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
