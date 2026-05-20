package dev.stagepass.auth.exception;

/**
 * Thrown when a refresh token is invalid, revoked, or expired.
 *
 * <p>Maps to HTTP 401 in {@link GlobalExceptionHandler}.
 *
 * <p>The message deliberately conflates "revoked" and "expired" — the caller
 * should not be told which case applies, as that could aid session fixation attacks.
 */
public class TokenRevokedException extends RuntimeException {
    public TokenRevokedException() {
        super("Refresh token has been revoked or has expired.");
    }
}
