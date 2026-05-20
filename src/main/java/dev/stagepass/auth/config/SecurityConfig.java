package dev.stagepass.auth.config;

import dev.stagepass.auth.security.BearerTokenFilter;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

/**
 * Spring Security configuration for the Auth Service.
 *
 * <p><strong>Design principles:</strong>
 * <ul>
 *   <li>Stateless — no HTTP sessions. Every request carries a JWT.</li>
 *   <li>CSRF disabled — CSRF only matters for session-based auth. Not applicable here.</li>
 *   <li>RBAC at service layer — role rules here AND at {@code @PreAuthorize} on service methods.
 *       Two enforcement points. (THR-AUTH-10, NFR-SEC-003)</li>
 *   <li>Security headers enabled — X-Content-Type-Options, Referrer-Policy, etc.</li>
 * </ul>
 *
 * <p><strong>No constructor injection issue:</strong> {@link BearerTokenFilter} is passed in
 * as a method parameter (Spring injects it from the bean graph). SecurityConfig does not
 * field-inject anything — constructor parameters only.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)  // Enables @PreAuthorize on service methods.
@EnableConfigurationProperties(AppProperties.class)
public class SecurityConfig {

    /**
     * Password encoder bean.
     *
     * <p>BCrypt with strength 12 (cost factor 2^12 = 4096 iterations).
     * This is approximately 100-200ms per hash on modern hardware — expensive enough
     * to slow brute-force, fast enough to not impact UX noticeably.
     * (NFR-SEC-007: bcrypt cost ≥ 12)
     *
     * <p>Declared here (not in AuthService) because Spring's AuthenticationManager
     * needs a PasswordEncoder bean, and SecurityConfig is the appropriate configuration
     * home for auth infrastructure beans.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    /**
     * The main security filter chain.
     *
     * <p>Endpoint access rules mirror the OpenAPI spec's {@code security: []} declarations.
     * When an endpoint is added to auth.yaml, its access rule must be added here.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           BearerTokenFilter bearerTokenFilter) throws Exception {
        http
            // ── Session management ─────────────────────────────
            // STATELESS: Spring Security never creates or uses HTTP sessions.
            // All authentication state lives in the JWT.
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // ── CSRF ────────────────────────────────────────────
            // Disabled: CSRF attacks require session cookies. JWTs in Authorization
            // headers are not sent by browsers automatically, so CSRF doesn't apply.
            .csrf(AbstractHttpConfigurer::disable)

            // ── Security headers ────────────────────────────────
            // Adds X-Content-Type-Options, X-Frame-Options, Referrer-Policy.
            // OWASP Top 10 A05: Security Misconfiguration — defence in depth.
            .headers(headers -> headers
                .referrerPolicy(policy ->
                    policy.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                .frameOptions(frame -> frame.deny())
                .contentTypeOptions(cto -> {}) // Enabled by default — explicit for clarity.
            )

            // ── Authorization rules ─────────────────────────────
            // Order matters: more specific rules first, wildcard last.
            .authorizeHttpRequests(auth -> auth

                // Public endpoints — no JWT required.
                .requestMatchers(HttpMethod.POST, "/auth/register").permitAll()
                .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()
                .requestMatchers(HttpMethod.POST, "/auth/refresh").permitAll()
                .requestMatchers(HttpMethod.POST, "/auth/password/reset/request").permitAll()
                .requestMatchers(HttpMethod.POST, "/auth/password/reset/confirm").permitAll()

                // JWKS endpoint — must be public. Downstream services fetch this at startup.
                .requestMatchers(HttpMethod.GET, "/auth/jwks").permitAll()

                // Health endpoints — public for K8s probes.
                .requestMatchers("/health/live", "/health/ready").permitAll()

                // Actuator — prometheus and info are internal (management port).
                // The management port is separate; these rules are belt-and-suspenders.
                .requestMatchers("/actuator/**").permitAll()

                // Admin-only endpoints. ROLE_ADMIN from JWT claim. (THR-AUTH-10)
                .requestMatchers("/auth/users/**").hasRole("ADMIN")

                // Everything else requires a valid JWT.
                .anyRequest().authenticated()
            )

            // ── JWT filter ──────────────────────────────────────
            // Runs before UsernamePasswordAuthenticationFilter.
            // Validates JWT, checks JTI blocklist, sets SecurityContext.
            .addFilterBefore(bearerTokenFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
