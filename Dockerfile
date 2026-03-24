# SECURITY: Use Eclipse Temurin (actively maintained, no Oracle licence issues).
# Match the Java version declared in build.gradle.kts (toolchain = 23).
# Pin to a specific digest in production to prevent supply-chain attacks.
FROM eclipse-temurin:23-jre-alpine

# SECURITY: Run as a non-root user — never run a JVM service as root.
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copy the fat JAR produced by `./gradlew bootJar`
COPY build/libs/*.jar app.jar

# Ensure the non-root user owns the JAR
RUN chown appuser:appgroup app.jar

USER appuser

# SECURITY: Expose only the application port; bind on all interfaces is handled
# by the orchestrator/reverse proxy, not the container.
EXPOSE 8080

# SECURITY: Pass secrets exclusively via environment variables, never build args.
# Required variables at runtime:
#   SPRING_DATASOURCE_URL, SPRING_DATASOURCE_USERNAME, SPRING_DATASOURCE_PASSWORD
#   RECAPTCHA_SECRET_KEY
#   ADMIN_INITIAL_PASSWORD (first run only)
ENTRYPOINT ["java", \
    "-Djava.security.egd=file:/dev/./urandom", \
    "-jar", "app.jar"]
