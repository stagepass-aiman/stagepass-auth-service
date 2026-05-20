package dev.stagepass.auth.exception;

import java.time.Instant;

/**
 * Thrown when a login attempt is made against a locked account.
 *
 * <p>Maps to HTTP 423 Locked in {@link GlobalExceptionHandler}.
 * The {@code lockedUntil} timestamp is included in the response so the client
 * can display a countdown ("try again in 28 minutes").
 *
 * <p>Locking is triggered by exceeding {@code app.lockout.max-attempts}
 * consecutive failed login attempts. Duration is {@code app.lockout.duration-minutes}.
 * Both are configurable per environment. (THR-AUTH-02)
 */
public class AccountLockedException extends RuntimeException {

    private final Instant lockedUntil;

    public AccountLockedException(Instant lockedUntil) {
        super("Account temporarily locked due to too many failed login attempts.");
        this.lockedUntil = lockedUntil;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }
}
