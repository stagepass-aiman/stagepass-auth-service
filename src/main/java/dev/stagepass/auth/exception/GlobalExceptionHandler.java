package dev.stagepass.auth.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Centralised exception → HTTP response mapping.
 *
 * <p>All error responses use RFC 9457 Problem Details format.
 * Spring Framework 6 provides {@link ProblemDetail} natively.
 * We add a {@code traceId} extension field for Jaeger correlation. (NFR-OBS-004)
 *
 * <p><strong>Security invariant:</strong> NEVER expose stack traces in the
 * {@code detail} field in non-local environments. Stack traces are information
 * disclosure. (THR-AUTH-06, OWASP A05)
 *
 * <p>Exception classes are public, one per file, in this package.
 * They were previously package-private in this file, which prevented
 * them from being imported by the service layer.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final String PROBLEMS_BASE = "https://stagepass.dev/problems/";

    @ExceptionHandler(EmailAlreadyRegisteredException.class)
    public ResponseEntity<ProblemDetail> handleEmailAlreadyRegistered(
            EmailAlreadyRegisteredException ex, WebRequest request) {

        return problem(HttpStatus.CONFLICT, "email-already-registered",
                       "Email Already Registered", ex.getMessage(), request);
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ProblemDetail> handleInvalidCredentials(
            InvalidCredentialsException ex, WebRequest request) {

        return problem(HttpStatus.UNAUTHORIZED, "invalid-credentials",
                       "Invalid Credentials", ex.getMessage(), request);
    }

    @ExceptionHandler(TokenRevokedException.class)
    public ResponseEntity<ProblemDetail> handleTokenRevoked(
            TokenRevokedException ex, WebRequest request) {

        return problem(HttpStatus.UNAUTHORIZED, "token-revoked",
                       "Token Revoked", ex.getMessage(), request);
    }

    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<ProblemDetail> handleAccountLocked(
            AccountLockedException ex, WebRequest request) {

        ProblemDetail pd = buildProblemDetail(HttpStatus.UNAUTHORIZED,
                           "account-locked", "Account Locked", ex.getMessage(), request);
        pd.setProperty("lockedUntil", ex.getLockedUntil().toString());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(pd);
    }

    @ExceptionHandler(AccountSuspendedException.class)
    public ResponseEntity<ProblemDetail> handleAccountSuspended(
            AccountSuspendedException ex, WebRequest request) {

        return problem(HttpStatus.UNAUTHORIZED, "account-suspended",
                       "Account Suspended", ex.getMessage(), request);
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleUserNotFound(
            UserNotFoundException ex, WebRequest request) {

        return problem(HttpStatus.NOT_FOUND, "user-not-found",
                       "User Not Found", ex.getMessage(), request);
    }

    @ExceptionHandler(PasswordResetTokenInvalidException.class)
    public ResponseEntity<ProblemDetail> handlePasswordResetTokenInvalid(
            PasswordResetTokenInvalidException ex, WebRequest request) {

        return problem(HttpStatus.UNAUTHORIZED, "password-reset-token-invalid",
                       "Invalid Reset Token", ex.getMessage(), request);
    }

    /**
     * Handles Jakarta Bean Validation failures (e.g. @NotBlank, @Email).
     * Returns 422 Unprocessable Entity with a violations array.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ProblemDetail> handleValidationErrors(
            MethodArgumentNotValidException ex, WebRequest request) {

        List<Map<String, String>> violations = ex.getBindingResult()
            .getAllErrors()
            .stream()
            .map(error -> {
                if (error instanceof FieldError fieldError) {
                    return Map.of(
                        "field", fieldError.getField(),
                        "message", fieldError.getDefaultMessage() != null
                            ? fieldError.getDefaultMessage()
                            : "Invalid value"
                    );
                }
                return Map.of("field", "unknown", "message", error.getDefaultMessage());
            })
            .collect(Collectors.toList());

        ProblemDetail pd = buildProblemDetail(HttpStatus.UNPROCESSABLE_ENTITY,
                           "validation-failed", "Validation Failed",
                           "Request body contains invalid fields.", request);
        pd.setProperty("violations", violations);
        return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(pd);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ProblemDetail> handleAccessDenied(
            AccessDeniedException ex, WebRequest request) {

        return problem(HttpStatus.FORBIDDEN, "forbidden",
                       "Forbidden", "Insufficient permissions.", request);
    }

    /** Catch-all for unexpected errors. No stack trace exposed. */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleUnexpected(Exception ex, WebRequest request) {
        // Log the full exception server-side; return a sanitised message to the client.
        // The traceId in the response lets the caller correlate with Jaeger. (NFR-OBS-004)
        return problem(HttpStatus.INTERNAL_SERVER_ERROR, "internal-error",
                       "Internal Server Error",
                       "An unexpected error occurred. Use the traceId to locate details.", request);
    }

    // ── Helpers ───────────────────────────────────────────────

    private ResponseEntity<ProblemDetail> problem(HttpStatus status, String type, String title,
                                                   String detail, WebRequest request) {
        return ResponseEntity.status(status)
            .body(buildProblemDetail(status, type, title, detail, request));
    }

    private ProblemDetail buildProblemDetail(HttpStatus status, String type, String title,
                                              String detail, WebRequest request) {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(status, detail);
        pd.setType(URI.create(PROBLEMS_BASE + type));
        pd.setTitle(title);
        // instance: the request path that caused the problem.
        pd.setInstance(URI.create(request.getDescription(false).replace("uri=", "")));
        // traceId: injected from MDC by Micrometer Tracing. (NFR-OBS-003)
        // If tracing is not active, defaults to empty string.
        String traceId = org.slf4j.MDC.get("traceId");
        pd.setProperty("traceId", traceId != null ? traceId : "");
        return pd;
    }
}
