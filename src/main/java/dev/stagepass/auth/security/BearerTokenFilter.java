package dev.stagepass.auth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Spring Security filter that validates RS256 JWTs on every request.
 *
 * <p><strong>Filter placement:</strong> registered before
 * {@code UsernamePasswordAuthenticationFilter} in the filter chain.
 * Spring Security's default session management is disabled (stateless).
 *
 * <p><strong>Validation sequence:</strong>
 * <ol>
 *   <li>Extract Bearer token from Authorization header. If absent, pass through
 *       (the endpoint's own access rules determine if authentication is required).</li>
 *   <li>Validate RS256 signature using {@link JwtService}. Rejects expired tokens,
 *       tampered payloads, wrong algorithm. (THR-AUTH-04)</li>
 *   <li>Check JTI blocklist via {@link JtiBlocklistService}. Rejects revoked tokens.
 *       (Logout / force-revoke support)</li>
 *   <li>Set {@link StagePassPrincipal} in Spring Security context.
 *       Role comes from JWT claim, NOT from headers. (THR-AUTH-10)</li>
 *   <li>Put userId and traceId in MDC for structured log correlation. (NFR-OBS-001)</li>
 * </ol>
 *
 * <p><strong>On invalid token present:</strong> returns 401 immediately.
 * Even on {@code permitAll()} endpoints — an invalid token is an explicit error.
 * An absent token on a {@code permitAll()} endpoint passes through normally.
 */
@Component
public class BearerTokenFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(BearerTokenFilter.class);
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String MDC_USER_ID = "userId";

    private final JwtService jwtService;
    private final JtiBlocklistService jtiBlocklistService;

    public BearerTokenFilter(JwtService jwtService, JtiBlocklistService jtiBlocklistService) {
        this.jwtService = jwtService;
        this.jtiBlocklistService = jtiBlocklistService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // No Authorization header — pass through. The security config's
        // authorizeHttpRequests rules will reject if the endpoint requires auth.
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(BEARER_PREFIX.length());

        try {
            // Step 1: Validate signature and expiry via JJWT (RS256 pinned).
            Claims claims = jwtService.validateAndExtractClaims(token);

            // Step 2: Check JTI blocklist — is this specific token revoked?
            String jti = jwtService.extractJti(claims);
            if (jtiBlocklistService.isRevoked(jti)) {
                log.warn("Rejected revoked JTI. jti={} userId={}", jti, claims.getSubject());
                writeUnauthorized(response, "Token has been revoked.");
                return;
            }

            // Step 3: Build principal from JWT claims only — NOT from request headers.
            // THR-AUTH-10: RBAC from claims, never from X-User-Role header.
            var principal = new StagePassPrincipal(
                jwtService.extractUserId(claims),
                jwtService.extractRole(claims),
                jti
            );

            // Step 4: Set in SecurityContext with the user's role as authority.
            // ROLE_ prefix is added per Spring Security convention.
            var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + principal.role().name()));
            var authentication = new UsernamePasswordAuthenticationToken(
                principal, null, authorities
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Step 5: Add userId to MDC for structured log correlation.
            // traceId and spanId are added automatically by Micrometer Tracing.
            // (NFR-OBS-001, NFR-OBS-004)
            MDC.put(MDC_USER_ID, principal.userId().toString());

            filterChain.doFilter(request, response);

        } catch (JwtException e) {
            // Covers: expired, tampered signature, invalid format, wrong algorithm.
            // Log at DEBUG — this is not unusual (expired tokens are common).
            log.debug("JWT validation failed: {}", e.getMessage());
            writeUnauthorized(response, "Invalid or expired token.");
        } catch (Exception e) {
            // Unexpected error during validation — log at ERROR.
            log.error("Unexpected error during JWT validation", e);
            writeUnauthorized(response, "Authentication processing failed.");
        } finally {
            // Always clear MDC to prevent userId leaking into unrelated log lines
            // on virtual thread reuse or filter chain continuation.
            MDC.remove(MDC_USER_ID);
        }
    }

    /**
     * Writes a minimal RFC 9457 Problem Details JSON 401 response.
     * We cannot use @RestControllerAdvice here (filter runs outside MVC dispatcher).
     */
    private static void writeUnauthorized(HttpServletResponse response, String detail)
            throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.getWriter().write(
            """
            {
              "type": "https://stagepass.dev/problems/unauthorized",
              "title": "Unauthorized",
              "status": 401,
              "detail": "%s",
              "instance": ""
            }
            """.formatted(detail)
        );
    }
}
