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

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies that CSRF protection is enforced on all state-changing endpoints.
 *
 * A missing or invalid CSRF token on any POST must return 403 Forbidden —
 * this prevents cross-site request forgery attacks where a malicious third-party
 * page tricks a logged-in user's browser into making requests on their behalf.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestConfig.class)
@DisplayName("CSRF Protection")
class CsrfProtectionTest {

    @Autowired
    private MockMvc mockMvc;

    // -----------------------------------------------------------------------
    // Login endpoint
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("POST /login without CSRF token → 403 Forbidden")
    void postLogin_withoutCsrf_returns403() throws Exception {
        mockMvc.perform(post("/login")
                        .param("username", "anyuser")
                        .param("password", "anypassword"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("POST /login with valid CSRF token → not 403 (redirects regardless of credentials)")
    void postLogin_withCsrf_notForbidden() throws Exception {
        mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", "anyuser")
                        .param("password", "wrongpassword"))
                .andExpect(status().is3xxRedirection()); // redirects to /login?error or /home
    }

    // -----------------------------------------------------------------------
    // Note creation endpoint (requires authentication)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("POST /home/add without CSRF token → 403 Forbidden")
    void postHomeAdd_withoutCsrf_returns403() throws Exception {
        mockMvc.perform(post("/home/add")
                        .param("title", "Test note")
                        .param("content", "Test content"))
                .andExpect(status().isForbidden());
    }

    // -----------------------------------------------------------------------
    // Logout endpoint
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("POST /logout without CSRF token → 403 Forbidden (prevents logout CSRF)")
    void postLogout_withoutCsrf_returns403() throws Exception {
        mockMvc.perform(post("/logout"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("POST /logout with valid CSRF token → 302 redirect (not 403)")
    void postLogout_withCsrf_redirects() throws Exception {
        mockMvc.perform(post("/logout").with(csrf()))
                .andExpect(status().is3xxRedirection());
    }

    // -----------------------------------------------------------------------
    // Note edit endpoint
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("POST /notes/{id}/edit without CSRF token → 403 Forbidden")
    void postNoteEdit_withoutCsrf_returns403() throws Exception {
        mockMvc.perform(post("/notes/1/edit")
                        .param("title", "New title")
                        .param("content", "New content"))
                .andExpect(status().isForbidden());
    }
}
