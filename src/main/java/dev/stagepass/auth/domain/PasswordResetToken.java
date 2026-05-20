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
 * JPA entity for the {@code password_reset_tokens} table.
 *
 * <p>Single-use, time-limited tokens for the forgot-password flow.
 * The raw token is embedded in the reset email link; only SHA-256(raw) is stored.
 *
 * <p>Consumption: when the user clicks the link, AuthService verifies
 * the token, sets used_at = now(), then proceeds with the password change.
 * A second use returns 401 because used_at is non-null.
 */
@Entity
@Table(name = "password_reset_tokens")
public class PasswordResetToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "token_hash", nullable = false, length = 64, unique = true)
    private String tokenHash;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    /** Null = not yet used. Set to now() on first (and only) valid consumption. */
    @Column(name = "used_at")
    private Instant usedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected PasswordResetToken() {}

    public static PasswordResetToken create(User user, String tokenHash, Instant expiresAt) {
        var prt = new PasswordResetToken();
        prt.user = user;
        prt.tokenHash = tokenHash;
        prt.expiresAt = expiresAt;
        prt.createdAt = Instant.now();
        return prt;
    }

    public boolean isValid() {
        return usedAt == null && Instant.now().isBefore(expiresAt);
    }

    /** Marks this token as consumed. Subsequent use will fail the isValid() check. */
    public void consume() {
        this.usedAt = Instant.now();
    }

    public UUID getId() { return id; }
    public User getUser() { return user; }
    public String getTokenHash() { return tokenHash; }
    public Instant getExpiresAt() { return expiresAt; }
    public Instant getUsedAt() { return usedAt; }
    public Instant getCreatedAt() { return createdAt; }
}
