package dev.stagepass.auth.security;

import dev.stagepass.auth.domain.UserRole;

import java.util.UUID;

/**
 * The authenticated principal stored in the Spring Security context.
 *
 * <p>Immutable record. Extracted from the validated JWT claims by
 * {@link BearerTokenFilter} and set as the Authentication principal.
 *
 * <p>Controllers access the current user via:
 * <pre>
 *   {@literal @}AuthenticationPrincipal StagePassPrincipal principal
 * </pre>
 *
 * <p>Role is extracted from JWT claims, NOT from the X-User-Role header.
 * Services must never trust the header for authorization decisions — only
 * the validated JWT claim. (THR-AUTH-10)
 */
public record StagePassPrincipal(UUID userId, UserRole role, String jti) {}
