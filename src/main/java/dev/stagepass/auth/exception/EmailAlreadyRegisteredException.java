package dev.stagepass.auth.exception;

/**
 * Thrown when a registration attempt uses an email address that already exists.
 *
 * <p>Maps to HTTP 409 Conflict in {@link GlobalExceptionHandler}.
 * The message is intentionally generic — do not expose whether the collision
 * is on email or any other field.
 */
public class EmailAlreadyRegisteredException extends RuntimeException {
    public EmailAlreadyRegisteredException() {
        super("An account with this email address already exists.");
    }
}
