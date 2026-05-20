package dev.stagepass.auth.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * JPA entity for the {@code refresh_tokens} table.
 *
 * <p>The raw refresh token is NEVER stored. Only SHA-256(rawToken) is persisted.
 * This means a DB dump does not yield usable refresh tokens.
 *
 * <p>Rotation-on-use: when a refresh token is presented, AuthService:
 * 1. Finds the token by hash
 * 2. Sets revoked_at = now() on the old token
 * 3. Inserts a new token
 * Both writes happen in the same @Transactional method — atomic.
 */
@Entity
@Table(name = "refresh_tokens")
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    /**
     * Owning user. FetchType.LAZY — we rarely need the full user object
     * when dealing with a refresh token; we usually only need user_id.
     */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    /**
     * SHA-256 hash of the raw opaque token, stored as lowercase hex (64 chars).
     * Lookup: compute SHA-256 of presented token, query by this field.
     */
    @Column(name = "token_hash", nullable = false, length = 64, unique = true)
    private String tokenHash;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    /**
     * Null = active token.
     * Non-null = token was revoked at this time.
     * On rotation, this is set atomically with the new token insert.
     */
    @Column(name = "revoked_at")
    private Instant revokedAt;

    /** Source IP at issuance — for anomaly detection (THR-AUTH-03). */
    @Column(name = "issued_from_ip", length = 45)
    private String issuedFromIp;

    /** User-Agent header at issuance — for anomaly detection (THR-AUTH-03). */
    @Column(name = "user_agent", length = 512)
    private String userAgent;

    @Column(name = "issued_at", nullable = false, updatable = false)
    private Instant issuedAt;

    protected RefreshToken() {}

    public static RefreshToken create(User user, String tokenHash, Instant expiresAt,
                                      String issuedFromIp, String userAgent) {
        var rt = new RefreshToken();
        rt.user = user;
        rt.tokenHash = tokenHash;
        rt.expiresAt = expiresAt;
        rt.issuedFromIp = issuedFromIp;
        rt.userAgent = userAgent;
        rt.issuedAt = Instant.now();
        return rt;
    }

    /** Marks this token as revoked. Called during rotation and logout. */
    public void revoke() {
        this.revokedAt = Instant.now();
    }

    public boolean isActive() {
        return revokedAt == null && Instant.now().isBefore(expiresAt);
    }

    public UUID getId() { return id; }
    public User getUser() { return user; }
    public String getTokenHash() { return tokenHash; }
    public Instant getExpiresAt() { return expiresAt; }
    public Instant getRevokedAt() { return revokedAt; }
    public Instant getIssuedAt() { return issuedAt; }
}
