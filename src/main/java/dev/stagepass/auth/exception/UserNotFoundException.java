package dev.stagepass.auth.exception;

/**
 * Thrown when an operation targets a userId that does not exist.
 *
 * <p>Maps to HTTP 404 in {@link GlobalExceptionHandler}.
 *
 * <p><strong>Note on user enumeration:</strong> this exception is only thrown on
 * authenticated admin endpoints or on the caller's own profile. It must NOT be thrown
 * from unauthenticated endpoints (e.g. login) where it could allow email enumeration.
 * Unauthenticated flows use {@link InvalidCredentialsException} instead.
 */
public class UserNotFoundException extends RuntimeException {
    public UserNotFoundException(String identifier) {
        super("User not found: " + identifier);
    }
}
