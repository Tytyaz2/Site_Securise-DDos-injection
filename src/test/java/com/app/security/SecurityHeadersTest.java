package com.app.security;

import com.app.TestConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies that every HTTP response carries the required security headers.
 *
 * These tests guard against regressions where a SecurityConfig refactor
 * accidentally removes a header directive.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestConfig.class)
@DisplayName("HTTP Security Headers")
class SecurityHeadersTest {

    @Autowired
    private MockMvc mockMvc;

    // The /login page is publicly accessible and always returns a full response —
    // ideal for checking headers without needing authentication.
    private static final String PUBLIC_URL = "/login";

    @Test
    @DisplayName("X-Frame-Options: DENY — prevents clickjacking")
    void xFrameOptions_isDeny() throws Exception {
        mockMvc.perform(get(PUBLIC_URL))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Frame-Options", "DENY"));
    }

    @Test
    @DisplayName("X-Content-Type-Options: nosniff — prevents MIME sniffing")
    void xContentTypeOptions_isNoSniff() throws Exception {
        mockMvc.perform(get(PUBLIC_URL))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"));
    }

    @Test
    @DisplayName("Strict-Transport-Security — HSTS enforced for 1 year with includeSubDomains (HTTPS only)")
    void hsts_presentWithCorrectMaxAge() throws Exception {
        // HSTS is only sent on HTTPS responses — simulate a secure request
        mockMvc.perform(get(PUBLIC_URL).secure(true))
                .andExpect(header().exists("Strict-Transport-Security"))
                .andExpect(header().string("Strict-Transport-Security",
                        containsString("max-age=31536000")))
                .andExpect(header().string("Strict-Transport-Security",
                        containsString("includeSubDomains")));
    }

    @Test
    @DisplayName("Referrer-Policy — strict-origin-when-cross-origin")
    void referrerPolicy_isStrict() throws Exception {
        mockMvc.perform(get(PUBLIC_URL))
                .andExpect(status().isOk())
                .andExpect(header().exists("Referrer-Policy"))
                .andExpect(header().string("Referrer-Policy",
                        containsString("strict-origin-when-cross-origin")));
    }

    @Test
    @DisplayName("Permissions-Policy — sensitive browser features are disabled")
    void permissionsPolicy_disablesSensitiveFeatures() throws Exception {
        mockMvc.perform(get(PUBLIC_URL))
                .andExpect(status().isOk())
                .andExpect(header().exists("Permissions-Policy"))
                .andExpect(header().string("Permissions-Policy", containsString("camera=()")))
                .andExpect(header().string("Permissions-Policy", containsString("microphone=()")))
                .andExpect(header().string("Permissions-Policy", containsString("geolocation=()")));
    }

    @Test
    @DisplayName("Content-Security-Policy — default-src 'self', object-src 'none', frame-ancestors 'none'")
    void contentSecurityPolicy_hasCriticalDirectives() throws Exception {
        mockMvc.perform(get(PUBLIC_URL))
                .andExpect(status().isOk())
                .andExpect(header().exists("Content-Security-Policy"))
                .andExpect(header().string("Content-Security-Policy",
                        containsString("default-src 'self'")))
                .andExpect(header().string("Content-Security-Policy",
                        containsString("object-src 'none'")))
                .andExpect(header().string("Content-Security-Policy",
                        containsString("frame-ancestors 'none'")))
                .andExpect(header().string("Content-Security-Policy",
                        containsString("form-action 'self'")));
    }

    @Test
    @DisplayName("CSP — reCAPTCHA sources are whitelisted for script-src and frame-src")
    void contentSecurityPolicy_allowsRecaptchaSources() throws Exception {
        mockMvc.perform(get(PUBLIC_URL))
                .andExpect(header().string("Content-Security-Policy",
                        containsString("https://www.google.com/recaptcha/")))
                .andExpect(header().string("Content-Security-Policy",
                        containsString("https://www.gstatic.com/recaptcha/")));
    }
}
