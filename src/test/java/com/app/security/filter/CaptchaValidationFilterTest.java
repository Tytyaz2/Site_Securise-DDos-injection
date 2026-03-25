package com.app.security.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for CaptchaValidationFilter.
 *
 * Tests that do NOT require a Google API response:
 * - Missing / blank token → redirect without touching Google
 * - Non-sensitive paths → filter is bypassed entirely
 * - GET requests → filter is bypassed (CAPTCHA only on POST)
 *
 * The actual Google verification path (valid/invalid token) is not tested
 * here because it requires a live network call with real credentials.
 * No Spring context required.
 */
@DisplayName("CaptchaValidationFilter — token presence checks")
class CaptchaValidationFilterTest {

    private CaptchaValidationFilter filter;

    @BeforeEach
    void setUp() {
        filter = new CaptchaValidationFilter("test-dummy-key");
    }

    // -----------------------------------------------------------------------
    // Missing / blank token on sensitive endpoints
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("POST /login without g-recaptcha-response → redirect to /login?error=captcha")
    void postLogin_missingToken_redirectsToCaptchaError() throws Exception {
        MockHttpServletRequest request = sensitivePost("/login");
        // No g-recaptcha-response parameter set
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getRedirectedUrl()).isEqualTo("/login?error=captcha");
    }

    @Test
    @DisplayName("POST /login with blank g-recaptcha-response → redirect to /login?error=captcha")
    void postLogin_blankToken_redirectsToCaptchaError() throws Exception {
        MockHttpServletRequest request = sensitivePost("/login");
        request.setParameter("g-recaptcha-response", "   "); // blank
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getRedirectedUrl()).isEqualTo("/login?error=captcha");
    }

    @Test
    @DisplayName("POST /register without g-recaptcha-response → redirect to /register?error=captcha")
    void postRegister_missingToken_redirectsToCaptchaError() throws Exception {
        MockHttpServletRequest request = sensitivePost("/register");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getRedirectedUrl()).isEqualTo("/register?error=captcha");
    }

    // -----------------------------------------------------------------------
    // Non-sensitive paths are bypassed
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("POST to a non-sensitive path → filter passes through (chain called)")
    void postNonSensitivePath_bypassesFilter() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/home/add");
        request.setServletPath("/home/add");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        // Chain must have been called (redirect URL is null = no redirect)
        assertThat(response.getRedirectedUrl()).isNull();
        assertThat(chain.getRequest()).isNotNull(); // chain.doFilter was invoked
    }

    // -----------------------------------------------------------------------
    // GET requests are always bypassed
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("GET /login → filter passes through (CAPTCHA is only for POST)")
    void getLogin_bypassesFilter() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login");
        request.setServletPath("/login");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getRedirectedUrl()).isNull();
        assertThat(chain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("GET /register → filter passes through")
    void getRegister_bypassesFilter() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/register");
        request.setServletPath("/register");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getRedirectedUrl()).isNull();
        assertThat(chain.getRequest()).isNotNull();
    }

    // -----------------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------------

    private MockHttpServletRequest sensitivePost(String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
        request.setServletPath(path);
        return request;
    }
}
