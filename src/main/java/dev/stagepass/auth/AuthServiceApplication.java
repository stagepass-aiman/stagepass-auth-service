package dev.stagepass.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import dev.stagepass.auth.config.AppProperties;

/**
 * Auth Service — entry point.
 *
 * <p>Responsibilities:
 * <ul>
 *   <li>User registration, login, logout, token refresh
 *   <li>RS256 JWT issuance with JWKS public key distribution
 *   <li>Redis JTI blocklist for token revocation
 *   <li>RBAC enforcement for the four-role model
 *       (CUSTOMER, ORGANISER, VENUE, ADMIN)
 *   <li>Admin user management (suspend, reinstate)
 *   <li>Password reset flow (email STUB in Phase 3)
 * </ul>
 *
 * <p><strong>Virtual threads (NFR-PERF-042):</strong>
 * Enabled via {@code spring.threads.virtual.enabled=true} in application.yml.
 * Spring Boot 3.2+ automatically uses virtual threads for the Tomcat executor,
 * replacing the default platform thread pool. bcrypt blocks a virtual thread
 * rather than a carrier thread, so bcrypt cost ≥12 has negligible throughput impact.
 *
 * <p><strong>No-arg main is deliberate:</strong>
 * All config comes from environment variables / Vault (12-Factor).
 * There are no defaults that would allow the service to start without
 * proper configuration. Missing required env vars cause fast-fail at startup.
 */
@SpringBootApplication
@EnableConfigurationProperties(AppProperties.class)
public class AuthServiceApplication {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceApplication.class);

    public static void main(String[] args) {
        var context = SpringApplication.run(AuthServiceApplication.class, args);
        log.info("Auth Service started. activeProfiles={}",
            java.util.Arrays.toString(context.getEnvironment().getActiveProfiles()));
    }
}
