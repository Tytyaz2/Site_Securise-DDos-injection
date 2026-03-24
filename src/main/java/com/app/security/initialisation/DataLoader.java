package com.app.security.initialisation;

import com.app.security.tableBDD.User;
import com.app.security.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Seeds the database with a default admin account on first startup.
 *
 * SECURITY:
 * - The admin password is loaded from the environment variable ADMIN_INITIAL_PASSWORD.
 *   If that variable is not set the application will refuse to start, preventing
 *   deployment with a known-weak default credential.
 * - A prominent WARN log is emitted if the default account is being created so that
 *   operators are aware and can rotate the credential immediately.
 *
 * Production checklist:
 *   1. Set ADMIN_INITIAL_PASSWORD to a long random value before first deploy.
 *   2. Change the password via the admin UI immediately after first login.
 *   3. Remove or disable this DataLoader once the admin account is established.
 */
@Component
public class DataLoader implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataLoader.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * The initial admin password MUST be provided via the ADMIN_INITIAL_PASSWORD
     * environment variable.  There is no hard-coded fallback.
     */
    @Value("${ADMIN_INITIAL_PASSWORD}")
    private String adminInitialPassword;

    public DataLoader(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        if (userRepository.findByUsername("admin") == null) {
            // Enforce a minimum password length to prevent trivially weak seeds
            if (adminInitialPassword == null || adminInitialPassword.length() < 16) {
                throw new IllegalStateException(
                    "ADMIN_INITIAL_PASSWORD must be set and at least 16 characters long. " +
                    "Set the ADMIN_INITIAL_PASSWORD environment variable before starting the application."
                );
            }

            User admin = new User(null, "admin", passwordEncoder.encode(adminInitialPassword), "ROLE_ADMIN");
            userRepository.save(admin);

            // WARN so this is always visible in production logs
            log.warn("=== DEFAULT ADMIN ACCOUNT CREATED — change the password immediately! ===");
        }
    }
}
