package dev.stagepass.auth.dto;

import dev.stagepass.auth.domain.UserRole;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * Request/Response DTOs for the Auth Service.
 *
 * <p>All types are Java 21 records — immutable, compact, no Lombok.
 * Bean Validation annotations are placed on record components.
 * Jackson deserialises into records via the canonical constructor.
 *
 * <p>Naming convention: inbound types end in {@code Request},
 * outbound types end in {@code Response} or describe what they represent.
 */
public final class AuthDtos {

    private AuthDtos() {} // Utility class — not instantiatable.

    // ══════════════════════════════════════════════════════
    // INBOUND — REQUEST TYPES
    // ══════════════════════════════════════════════════════

    /**
     * POST /auth/register
     * (NFR-SEC-007: password → bcrypt cost ≥ 12 in AuthService)
     */
    public record RegisterRequest(
        @NotBlank @Email(message = "Must be a valid email address")
        @Size(max = 254)
        String email,

        @NotBlank
        @Size(min = 8, max = 128, message = "Password must be 8–128 characters")
        String password,

        @NotNull
        UserRole role,

        @NotBlank
        @Size(min = 1, max = 100, message = "Display name must be 1–100 characters")
        String displayName
    ) {}

    /** POST /auth/login */
    public record LoginRequest(
        @NotBlank @Email String email,
        @NotBlank String password
    ) {}

    /** POST /auth/refresh */
    public record RefreshRequest(
        @NotBlank String refreshToken
    ) {}

    /** POST /auth/password/change */
    public record ChangePasswordRequest(
        @NotBlank String currentPassword,
        @NotBlank @Size(min = 8, max = 128) String newPassword
    ) {}

    /** POST /auth/password/reset/confirm */
    public record ConfirmPasswordResetRequest(
        @NotBlank String token,
        @NotBlank @Size(min = 8, max = 128) String newPassword
    ) {}

    /** PUT /auth/me */
    public record UpdateProfileRequest(
        @NotBlank @Size(min = 1, max = 100) String displayName
    ) {}

    /** POST /auth/users/{userId}/suspend */
    public record SuspendUserRequest(
        @NotBlank @Size(max = 500) String reason
    ) {}

    /** POST /auth/password/reset/request */
    public record PasswordResetRequestBody(
        @NotBlank @Email String email
    ) {}

    // ══════════════════════════════════════════════════════
    // OUTBOUND — RESPONSE TYPES
    // ══════════════════════════════════════════════════════

    /**
     * Token pair returned on register, login, and refresh.
     * expiresIn is the access token lifetime in seconds (≤ 900).
     */
    public record TokenPair(
        String accessToken,
        String refreshToken,
        int expiresIn,
        String tokenType
    ) {
        public static TokenPair of(String accessToken, String refreshToken, int expiresIn) {
            return new TokenPair(accessToken, refreshToken, expiresIn, "Bearer");
        }
    }

    /** GET /auth/me and admin user listing. */
    public record UserProfileResponse(
        String userId,
        String email,
        String role,
        String displayName,
        String status,
        String createdAt,
        String updatedAt
    ) {}

    /** Paginated user list for Admin endpoints. */
    public record UserPage(
        java.util.List<UserProfileResponse> items,
        String nextCursor,
        String prevCursor
    ) {}
}
