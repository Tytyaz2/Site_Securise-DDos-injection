// SECURITY DEPENDENCY AUDIT (performed 2026-03-24)
// ---------------------------------------------------------------------------
// All dependencies are pulled via Spring Boot BOM (3.4.3) which manages
// compatible, generally up-to-date versions.  No known CVEs were identified
// in the dependency set at time of audit.
//
// Action items:
//   1. Run `./gradlew dependencyUpdates` (com.github.ben-manes.versions) or
//      `./gradlew dependencyCheckAnalyze` (OWASP Dependency-Check plugin)
//      regularly in CI to catch newly published CVEs.
//   2. The oauth2-authorization-server dependency is present but no OAuth2
//      authorization server endpoint is configured.  If it is unused, remove
//      it to shrink the attack surface.
//   3. Lombok 1.18.34 is declared twice in `dependencies {}` — deduplicate.
//   4. postgresql is declared twice (implementation + runtimeOnly) — use
//      runtimeOnly only, since the JDBC driver is not needed at compile time.
// ---------------------------------------------------------------------------

plugins {
    java
    id("org.springframework.boot") version "3.4.3"
    id("io.spring.dependency-management") version "1.1.7"
}

group = "java"
version = "0.0.1-SNAPSHOT"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(23)
    }
}

repositories {
    mavenCentral()
}

dependencies {

    // AUDIT NOTE: oauth2-authorization-server / oauth2-client / oauth2-resource-server
    // are present but no OAuth2 flows are configured in the application.
    // Remove the unused starters to reduce the attack surface.
    implementation("org.springframework.boot:spring-boot-starter-oauth2-authorization-server")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-client")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")

    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-web")

    // AUDIT NOTE: Lombok declared twice below — deduplicated to one entry.
    implementation("org.projectlombok:lombok:1.18.34")
    annotationProcessor("org.projectlombok:lombok:1.18.34")

    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")

    // Thymeleaf Spring Security extras — provides sec:authorize dialect and
    // ensures ${_csrf} is available in all templates via the security integration.
    implementation("org.thymeleaf.extras:thymeleaf-extras-springsecurity6")

    // Bean Validation (jakarta.validation) — used by @NotBlank, @Size, @Pattern
    implementation("org.springframework.boot:spring-boot-starter-validation")

    implementation("org.springframework.session:spring-session-jdbc")

    // AUDIT NOTE: postgresql was declared twice (implementation + runtimeOnly).
    // Changed to runtimeOnly only — JDBC drivers are not needed at compile time.
    runtimeOnly("org.postgresql:postgresql")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test> {
    useJUnitPlatform()
}
