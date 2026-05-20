package dev.stagepass.auth.exception;

/**
 * Thrown when a password reset token is invalid, expired, or already used.
 *
 * <p>Maps to HTTP 400 in {@link GlobalExceptionHandler}.
 *
 * <p>The message deliberately does not distinguish between "expired", "already used",
 * and "not found". All three cases are presented identically to prevent oracle attacks
 * where an attacker determines token lifetime or usage state by observing error codes.
 */
public class PasswordResetTokenInvalidException extends RuntimeException {
    public PasswordResetTokenInvalidException() {
        super("Password reset token is invalid or has expired.");
    }
}
