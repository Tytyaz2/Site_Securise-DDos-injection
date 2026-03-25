package com.app;

import com.app.security.filter.CaptchaValidationFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.io.IOException;

/**
 * Shared test configuration:
 * - Fast BCrypt (strength 4) to keep tests quick
 * - No-op CAPTCHA filter (avoids real Google API calls)
 */
@TestConfiguration
public class TestConfig {

    /** Override BCrypt strength 12 → 4 so tests don't hang hashing passwords. */
    @Bean
    @Primary
    public PasswordEncoder testPasswordEncoder() {
        return new BCryptPasswordEncoder(4);
    }

    /** Pass-through CAPTCHA filter — no Google API calls in tests. */
    @Bean
    @Primary
    public CaptchaValidationFilter noOpCaptchaFilter() {
        return new CaptchaValidationFilter("test-dummy-key") {
            @Override
            public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
                    throws IOException, ServletException {
                chain.doFilter(req, res);
            }
        };
    }
}
