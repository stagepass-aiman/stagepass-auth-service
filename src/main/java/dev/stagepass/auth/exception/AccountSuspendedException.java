package dev.stagepass.auth.exception;

/**
 * Thrown when a login or action is attempted on a SUSPENDED account.
 *
 * <p>Maps to HTTP 403 in {@link GlobalExceptionHandler}.
 * Suspension is an Admin action recorded in {@code admin_audit_log}.
 */
public class AccountSuspendedException extends RuntimeException {
    public AccountSuspendedException() {
        super("This account has been suspended. Contact support for assistance.");
    }
}
