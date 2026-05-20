# ═══════════════════════════════════════════════════════════════════════════════
# Stage 1 — Build
# ═══════════════════════════════════════════════════════════════════════════════
# Using the Eclipse Temurin Alpine image for a small builder footprint.
# Maven dependencies are downloaded in a separate layer so they are cached
# when only source code changes (common in development and CI).
FROM maven:3.9-eclipse-temurin-21-alpine AS builder

WORKDIR /build

# ── Dependency cache layer ────────────────────────────────────────────────────
# Copy pom.xml first and download dependencies in a separate RUN.
# Docker caches this layer unless pom.xml changes.
# This makes incremental builds ~5x faster in CI when only source changes.
COPY pom.xml .
RUN mvn dependency:go-offline -q

# ── Source compilation ────────────────────────────────────────────────────────
COPY src ./src
# -DskipTests: tests run in the CI pipeline as a separate step before this build.
# Running them inside Docker would require Testcontainers + Docker-in-Docker, which
# is complex and slow. The CI pipeline is the quality gate; this stage is just packaging.
RUN mvn package -DskipTests -q

# ── Layered JAR extraction ────────────────────────────────────────────────────
# Spring Boot 3 produces a layered JAR by default.
# Extracting layers allows Docker to cache dependencies separately from application code.
# Layer order (innermost to outermost = most stable to most volatile):
#   1. dependencies (changes rarely — only on pom.xml change)
#   2. spring-boot-loader (changes only on Spring Boot upgrade)
#   3. snapshot-dependencies (internal snapshots — changes occasionally)
#   4. application (changes on every code change — smallest layer)
WORKDIR /build/target/extracted
RUN java -Djarmode=layertools -jar /build/target/*.jar extract

# ═══════════════════════════════════════════════════════════════════════════════
# Stage 2 — Runtime
# ═══════════════════════════════════════════════════════════════════════════════
# Distroless Java 21 — no shell, no package manager, minimal attack surface.
# Distroless images have no known CVEs at publish time (unlike alpine + JRE).
# The nonroot variant runs as UID 65532 by default.
FROM gcr.io/distroless/java21-debian12:nonroot AS runtime

WORKDIR /app

# Copy extracted layers in order of volatility (most stable first).
# Docker rebuilds only from the first changed layer onwards.
COPY --from=builder /build/target/extracted/dependencies/ ./
COPY --from=builder /build/target/extracted/spring-boot-loader/ ./
COPY --from=builder /build/target/extracted/snapshot-dependencies/ ./
COPY --from=builder /build/target/extracted/application/ ./

# ── Security ──────────────────────────────────────────────────────────────────
# Distroless nonroot image already runs as UID 65532.
# Explicitly declare it for clarity and to satisfy container scanners.
USER 65532:65532

# ── Config ────────────────────────────────────────────────────────────────────
# Port exposed by the service.
# The actual port is also declared in application.yml (server.port=8081).
EXPOSE 8081

# ── Health check (Docker/Kubernetes fallback) ─────────────────────────────────
# Kubernetes uses readiness/liveness probes from the Helm chart.
# This HEALTHCHECK is for docker-compose and standalone docker run scenarios.
# Note: distroless has no curl — use wget if needed, or use the exec form with java.
# In production Kubernetes (Phase 9), Kubernetes probes supersede this.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD ["java", "-cp", "BOOT-INF/lib/*:.", \
       "dev.stagepass.auth.healthcheck.DockerHealthCheck"] || exit 1

# ── Entrypoint ────────────────────────────────────────────────────────────────
# Use the layered JAR launcher class directly (avoids JVM startup of a nested JAR).
# JVM flags:
#   -XX:+UseContainerSupport   respect cgroup memory/CPU limits (default in JDK 11+, explicit for clarity)
#   -XX:MaxRAMPercentage=75.0  use 75% of cgroup memory limit as heap max
#   -Djava.security.egd=...    faster SecureRandom on Linux (avoids blocking /dev/random)
ENTRYPOINT ["java", \
  "-XX:+UseContainerSupport", \
  "-XX:MaxRAMPercentage=75.0", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "org.springframework.boot.loader.launch.JarLauncher"]
