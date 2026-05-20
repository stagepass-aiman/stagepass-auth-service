package dev.stagepass.auth.security;

import dev.stagepass.auth.config.AppProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Loads the RS256 keypair from environment variables at application startup.
 *
 * <p>The private key is DER-encoded PKCS8, Base64-encoded (no PEM headers).
 * The public key is DER-encoded X.509/SPKI, Base64-encoded (no PEM headers).
 *
 * <p>In production, Vault Agent injects these as environment variables before
 * the JVM starts. The application never reads from Vault directly — Vault Agent
 * handles credential lifecycle. (THR-AUTH-01, NFR-SEC-008)
 *
 * <p>Key generation for local development:
 * <pre>
 *   # Generate RSA-4096 private key
 *   openssl genrsa -out private.pem 4096
 *   # Export private key as DER Base64 (no headers, no newlines)
 *   openssl pkcs8 -topk8 -inform PEM -outform DER -in private.pem -nocrypt | base64 -w0
 *   # Export public key as DER Base64
 *   openssl rsa -in private.pem -pubout -outform DER | base64 -w0
 * </pre>
 *
 * <p><strong>Security invariant:</strong> the private key is NEVER logged.
 * The {@link #toString()} method is overridden to prevent accidental exposure
 * in log statements that call toString() on this bean.
 */
@Component
public class RsaKeyProvider {

    private static final Logger log = LoggerFactory.getLogger(RsaKeyProvider.class);

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;
    private final String keyId;

    /**
     * Constructor injection — keys are loaded and parsed eagerly at startup.
     * If parsing fails (bad Base64, wrong key format), the application fails fast
     * with a clear error rather than an obscure NPE at request time.
     *
     * @throws IllegalStateException if keys cannot be loaded or parsed
     */
    public RsaKeyProvider(AppProperties properties) {
        this.keyId = properties.jwt().keyId();

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            // Parse private key from DER-encoded PKCS8 Base64.
            byte[] privateKeyBytes = Base64.getDecoder().decode(properties.jwt().privateKey());
            this.privateKey = (RSAPrivateKey) keyFactory.generatePrivate(
                new PKCS8EncodedKeySpec(privateKeyBytes)
            );

            // Parse public key from DER-encoded X.509 Base64.
            byte[] publicKeyBytes = Base64.getDecoder().decode(properties.jwt().publicKey());
            this.publicKey = (RSAPublicKey) keyFactory.generatePublic(
                new X509EncodedKeySpec(publicKeyBytes)
            );

            // Verify key pair consistency: the modulus of both keys must match.
            if (!privateKey.getModulus().equals(publicKey.getModulus())) {
                throw new IllegalStateException(
                    "RSA key pair mismatch: private and public keys have different moduli. " +
                    "Ensure AUTH_RSA_PRIVATE_KEY and AUTH_RSA_PUBLIC_KEY are from the same keypair."
                );
            }

            // Log key fingerprint (safe — public key info only, no private material).
            log.info("RSA keypair loaded. kid={} modulus_bits={}",
                keyId, publicKey.getModulus().bitLength());

        } catch (NoSuchAlgorithmException e) {
            // RSA is always available in any standard JRE — this should never happen.
            throw new IllegalStateException("RSA algorithm not available in this JRE", e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException(
                "Failed to parse RSA keys. Verify that AUTH_RSA_PRIVATE_KEY is DER-encoded " +
                "PKCS8 Base64, and AUTH_RSA_PUBLIC_KEY is DER-encoded X.509 Base64.", e);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(
                "Failed to Base64-decode RSA key material. Ensure no PEM headers, " +
                "no newlines, and no whitespace in the environment variable values.", e);
        }
    }

    public RSAPrivateKey getPrivateKey() { return privateKey; }
    public RSAPublicKey getPublicKey() { return publicKey; }
    public String getKeyId() { return keyId; }

    @Override
    public String toString() {
        // NEVER expose key material in toString — prevents accidental logging.
        return "RsaKeyProvider{kid=" + keyId + ", modulus_bits=" + publicKey.getModulus().bitLength() + "}";
    }
}
