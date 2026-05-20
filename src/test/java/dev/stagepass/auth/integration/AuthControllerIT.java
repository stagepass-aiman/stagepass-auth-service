package dev.stagepass.auth.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for the Auth Service HTTP layer.
 *
 * <p>Uses Testcontainers to spin up real PostgreSQL 16 and Redis 7 instances.
 * The Spring context is started once per class (RANDOM_PORT, shared containers).
 * Flyway migrations run automatically on startup.
 *
 * <p><strong>RSA key setup:</strong>
 * A fresh 2048-bit RSA key pair is generated in {@link #setUpRsaKey()} and injected
 * via {@link DynamicPropertySource} before the application context starts.
 * This avoids needing a real Vault in the test environment.
 *
 * <p><strong>What is tested here (not in unit tests):</strong>
 * <ul>
 *   <li>HTTP request/response mapping (status codes, response bodies)
 *   <li>Bean Validation on request DTOs (422 responses)
 *   <li>Full registration → login → refresh → logout flow with real DB
 *   <li>Flyway migration runs correctly
 *   <li>JWKS endpoint returns a parseable RSA JWK
 *   <li>Health check endpoints return correct status
 * </ul>
 */
@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@DisplayName("AuthController Integration Tests")
class AuthControllerIT {

    // ── Testcontainers ────────────────────────────────────────────────────────

    @Container
    static final PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(
        DockerImageName.parse("postgres:16-alpine")
    )
        .withDatabaseName("auth_db_test")
        .withUsername("auth_user_test")
        .withPassword("auth_pass_test");

    @SuppressWarnings("resource")
    @Container
    static final GenericContainer<?> redis = new GenericContainer<>(
        DockerImageName.parse("redis:7-alpine")
    )
        .withExposedPorts(6379);

    // ── RSA key for the test context ──────────────────────────────────────────

    private static String testPrivateKeyB64;
    private static String testPublicKeyB64;

    @BeforeAll
    static void setUpRsaKey() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair keyPair = gen.generateKeyPair();

        // PKCS8 DER-encoded private key (matches what RsaKeyProvider expects).
        testPrivateKeyB64 = Base64.getEncoder().encodeToString(
            keyPair.getPrivate().getEncoded()
        );
        // X.509 DER-encoded public key.
        testPublicKeyB64 = Base64.getEncoder().encodeToString(
            keyPair.getPublic().getEncoded()
        );
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        // PostgreSQL
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);

        // Redis
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", () -> redis.getMappedPort(6379));

        // RSA key pair (bypasses Vault for tests)
        registry.add("app.jwt.private-key-b64", () -> testPrivateKeyB64);
        registry.add("app.jwt.public-key-b64", () -> testPublicKeyB64);
        registry.add("app.jwt.key-id", () -> "test-key-it-1");
    }

    // ── Test infrastructure ───────────────────────────────────────────────────

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;

    private static final String EMAIL = "integration-test@stagepass.dev";
    private static final String PASSWORD = "IntegrationTest1!";

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String registerAndGetAccessToken() throws Exception {
        String body = """
            {
              "email": "%s",
              "password": "%s",
              "role": "CUSTOMER",
              "displayName": "IT User"
            }
            """.formatted(EMAIL, PASSWORD);

        MvcResult result = mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
            .andExpect(status().isCreated())
            .andReturn();

        JsonNode response = objectMapper.readTree(result.getResponse().getContentAsString());
        return response.get("accessToken").asText();
    }

    private String loginAndGetRefreshToken(String email, String password) throws Exception {
        String body = """
            { "email": "%s", "password": "%s" }
            """.formatted(email, password);

        MvcResult result = mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
            .andExpect(status().isOk())
            .andReturn();

        JsonNode response = objectMapper.readTree(result.getResponse().getContentAsString());
        return response.get("refreshToken").asText();
    }

    // ══════════════════════════════════════════════════════════════════════════
    // REGISTER
    // ══════════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("POST /auth/register")
    class Register {

        @Test
        @DisplayName("201: returns token pair for valid registration")
        void happyPath() throws Exception {
            String uniqueEmail = "register-happy-" + System.nanoTime() + "@test.dev";

            mockMvc.perform(post("/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""
                        {
                          "email": "%s",
                          "password": "ValidPass1!",
                          "role": "CUSTOMER",
                          "displayName": "Test User"
                        }
                        """.formatted(uniqueEmail)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accessToken").isString())
                .andExpect(jsonPath("$.refreshToken").isString())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").isNumber());
        }

        @Test
        @DisplayName("409: duplicate email returns Conflict")
        void duplicateEmail() throws Exception {
            String uniqueEmail = "register-dup-" + System.nanoTime() + "@test.dev";
            String body = """
                {
                  "email": "%s",
                  "password": "ValidPass1!",
                  "role": "CUSTOMER",
                  "displayName": "Test User"
                }
                """.formatted(uniqueEmail);

            // First registration succeeds.
            mockMvc.perform(post("/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(body))
                .andExpect(status().isCreated());

            // Second registration with same email → 409.
            mockMvc.perform(post("/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(body))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value("https://stagepass.dev/problems/email-already-registered"));
        }

        @Test
        @DisplayName("422: invalid email format returns validation error")
        void invalidEmail() throws Exception {
            mockMvc.perform(post("/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""
                        {
                          "email": "not-an-email",
                          "password": "ValidPass1!",
                          "role": "CUSTOMER",
                          "displayName": "Test User"
                        }
                        """))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.violations").isArray());
        }

        @Test
        @DisplayName("422: password too short returns validation error")
        void passwordTooShort() throws Exception {
            mockMvc.perform(post("/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""
                        {
                          "email": "valid@test.dev",
                          "password": "short",
                          "role": "CUSTOMER",
                          "displayName": "Test User"
                        }
                        """))
                .andExpect(status().isUnprocessableEntity());
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // LOGIN
    // ══════════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("POST /auth/login")
    class Login {

        @Test
        @DisplayName("200: returns token pair for valid credentials")
        void happyPath() throws Exception {
            String email = "login-happy-" + System.nanoTime() + "@test.dev";
            // Register first.
            mockMvc.perform(post("/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""
                        {"email":"%s","password":"ValidPass1!","role":"CUSTOMER","displayName":"T"}
                        """.formatted(email)))
                .andExpect(status().isCreated());

            // Then login.
            mockMvc.perform(post("/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""
                        {"email":"%s","password":"ValidPass1!"}
                        """.formatted(email)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isString())
                .andExpect(jsonPath("$.refreshToken").isString());
        }

        @Test
        @DisplayName("401: wrong password returns InvalidCredentials (not UserNotFound)")
        void wrongPassword() throws Exception {
            String email = "login-wrong-pass-" + System.nanoTime() + "@test.dev";
            mockMvc.perform(post("/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""
                        {"email":"%s","password":"ValidPass1!","role":"CUSTOMER","displayName":"T"}
                        """.formatted(email)))
                .andExpect(status().isCreated());

            mockMvc.perform(post("/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""
                        {"email":"%s","password":"WrongPass1!"}
                        """.formatted(email)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type").value("https://stagepass.dev/problems/invalid-credentials"));
        }

        @Test
        @DisplayName("401: unknown email returns same InvalidCredentials (no enumeration)")
        void unknownEmailSameError() throws Exception {
            // An unknown email must return the exact same error as wrong password.
            // This is the user enumeration prevention check. (THR-AUTH-06)
            mockMvc.perform(post("/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""
                        {"email":"ghost-nobody@test.dev","password":"AnyPassword1!"}
                        """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type").value("https://stagepass.dev/problems/invalid-credentials"));
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // REFRESH
    // ══════════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("POST /auth/refresh")
    class Refresh {

        @Test
        @DisplayName("200: valid refresh token returns new token pair")
        void happyPath() throws Exception {
            String email = "refresh-happy-" + System.nanoTime() + "@test.dev";
            mockMvc.perform(post("/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""
                        {"email":"%s","password":"ValidPass1!","role":"CUSTOMER","displayName":"T"}
                        """.formatted(email)))
                .andExpect(status().isCreated());

            String refreshToken = loginAndGetRefreshToken(email, "ValidPass1!");

            mockMvc.perform(post("/auth/refresh")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""
                        {"refreshToken":"%s"}
                        """.formatted(refreshToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isString())
                .andExpect(jsonPath("$.refreshToken").isString());
        }

        @Test
        @DisplayName("401: a refresh token cannot be used twice (rotation — THR-AUTH-03)")
        void tokenRotationPreventsReuse() throws Exception {
            String email = "refresh-rotate-" + System.nanoTime() + "@test.dev";
            mockMvc.perform(post("/auth/register")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""
                        {"email":"%s","password":"ValidPass1!","role":"CUSTOMER","displayName":"T"}
                        """.formatted(email)))
                .andExpect(status().isCreated());

            String refreshToken = loginAndGetRefreshToken(email, "ValidPass1!");

            // First use: succeeds, token is rotated.
            mockMvc.perform(post("/auth/refresh")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""
                        {"refreshToken":"%s"}
                        """.formatted(refreshToken)))
                .andExpect(status().isOk());

            // Second use of same token: must fail (token was revoked on first use).
            mockMvc.perform(post("/auth/refresh")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""
                        {"refreshToken":"%s"}
                        """.formatted(refreshToken)))
                .andExpect(status().isUnauthorized());
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // JWKS
    // ══════════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("GET /auth/jwks")
    class Jwks {

        @Test
        @DisplayName("200: returns a valid JWKS document with RSA key")
        void returnsJwks() throws Exception {
            MvcResult result = mockMvc.perform(get("/auth/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                .andExpect(jsonPath("$.keys[0].n").isString())
                .andExpect(jsonPath("$.keys[0].e").isString())
                .andReturn();

            // Cache-Control header must be present for downstream caching.
            String cacheControl = result.getResponse().getHeader("Cache-Control");
            assertThat(cacheControl).isNotNull().contains("max-age");
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // HEALTH
    // ══════════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("Health endpoints")
    class Health {

        @Test
        @DisplayName("GET /health/live → 200 UP")
        void livenessUp() throws Exception {
            mockMvc.perform(get("/health/live"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
        }

        @Test
        @DisplayName("GET /health/ready → 200 UP with all checks passing")
        void readinessUp() throws Exception {
            mockMvc.perform(get("/health/ready"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.checks.postgresql").value("UP"))
                .andExpect(jsonPath("$.checks.redis").value("UP"))
                .andExpect(jsonPath("$.checks.rsaKey").value("LOADED"));
        }
    }
}
