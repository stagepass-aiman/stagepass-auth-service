package dev.stagepass.auth.exception;

/**
 * Thrown when login credentials do not match any account.
 *
 * <p>Maps to HTTP 401 in {@link GlobalExceptionHandler}.
 *
 * <p><strong>OWASP OAT-007 — User Enumeration Prevention:</strong>
 * The message is deliberately vague: "Invalid email or password."
 * It must NEVER say "email not found" or "wrong password" separately,
 * as that allows an attacker to enumerate valid email addresses.
 */
public class InvalidCredentialsException extends RuntimeException {
    public InvalidCredentialsException() {
        super("Invalid email or password.");
    }
}
