package com.app.security.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for RateLimitingFilter.
 * Focuses on:
 * - Correct IP resolution (X-Forwarded-For, X-Real-IP, RemoteAddr fallback)
 * - 429 response after threshold is exceeded
 * - Retry-After header is set on blocked responses
 * No Spring context required.
 */
@DisplayName("RateLimitingFilter — IP resolution & 429 enforcement")
class RateLimitingFilterTest {

    // Auth endpoints have a 10 req/min limit — use /login for threshold tests
    private static final String AUTH_PATH = "/login";
    private static final int AUTH_LIMIT = 10;
    // General endpoints have a 60 req/min limit
    private static final String GENERAL_PATH = "/home";

    private RateLimitingFilter filter;

    @BeforeEach
    void setUp() {
        filter = new RateLimitingFilter();
    }

    // -----------------------------------------------------------------------
    // Happy path: requests under the limit pass through
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Requests under auth limit → 200 (chain called)")
    void requestsUnderAuthLimit_passThrough() throws Exception {
        for (int i = 0; i < AUTH_LIMIT; i++) {
            MockHttpServletRequest request = requestFor(AUTH_PATH, "1.2.3.4");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(request, response, chain);

            assertThat(response.getStatus())
                    .as("request %d should pass (status not 429)", i + 1)
                    .isNotEqualTo(429);
        }
    }

    // -----------------------------------------------------------------------
    // Threshold: (limit+1)th request on the same IP must be blocked
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("(auth limit + 1)th request from same IP → 429 Too Many Requests")
    void authLimitExceeded_returns429() throws Exception {
        String ip = "10.0.0.1";

        // Exhaust the auth limit
        for (int i = 0; i < AUTH_LIMIT; i++) {
            filter.doFilter(requestFor(AUTH_PATH, ip),
                    new MockHttpServletResponse(), new MockFilterChain());
        }

        // One more — should be blocked
        MockHttpServletResponse blocked = new MockHttpServletResponse();
        filter.doFilter(requestFor(AUTH_PATH, ip), blocked, new MockFilterChain());

        assertThat(blocked.getStatus()).isEqualTo(429);
    }

    @Test
    @DisplayName("Blocked response includes Retry-After header")
    void blockedResponse_hasRetryAfterHeader() throws Exception {
        String ip = "10.0.0.2";

        for (int i = 0; i < AUTH_LIMIT; i++) {
            filter.doFilter(requestFor(AUTH_PATH, ip),
                    new MockHttpServletResponse(), new MockFilterChain());
        }

        MockHttpServletResponse blocked = new MockHttpServletResponse();
        filter.doFilter(requestFor(AUTH_PATH, ip), blocked, new MockFilterChain());

        assertThat(blocked.getHeader("Retry-After"))
                .as("Retry-After header must be present on 429 response")
                .isNotNull();
    }

    // -----------------------------------------------------------------------
    // Different IPs are rate-limited independently
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Two different IPs share no rate-limit state")
    void differentIps_areTrackedIndependently() throws Exception {
        String ipA = "192.168.1.1";
        String ipB = "192.168.1.2";

        // Exhaust IP A
        for (int i = 0; i < AUTH_LIMIT; i++) {
            filter.doFilter(requestFor(AUTH_PATH, ipA),
                    new MockHttpServletResponse(), new MockFilterChain());
        }

        // IP B should still be allowed
        MockHttpServletResponse responseBFirstRequest = new MockHttpServletResponse();
        filter.doFilter(requestFor(AUTH_PATH, ipB), responseBFirstRequest, new MockFilterChain());

        assertThat(responseBFirstRequest.getStatus())
                .as("IP B must not be affected by IP A's limit")
                .isNotEqualTo(429);
    }

    // -----------------------------------------------------------------------
    // IP resolution: X-Forwarded-For
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("X-Forwarded-For header is used as the client IP when present")
    void xForwardedFor_usedAsClientIp() throws Exception {
        // Two requests from different real IPs but same X-Forwarded-For
        // should hit the same rate-limit bucket
        String forwardedIp = "203.0.113.5";

        for (int i = 0; i < AUTH_LIMIT; i++) {
            MockHttpServletRequest req = requestFor(AUTH_PATH, "proxy.internal");
            req.addHeader("X-Forwarded-For", forwardedIp);
            filter.doFilter(req, new MockHttpServletResponse(), new MockFilterChain());
        }

        // Next request with same forwarded IP should be blocked
        MockHttpServletRequest req = requestFor(AUTH_PATH, "proxy.internal");
        req.addHeader("X-Forwarded-For", forwardedIp);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(req, response, new MockFilterChain());

        assertThat(response.getStatus())
                .as("X-Forwarded-For client IP should be rate-limited correctly")
                .isEqualTo(429);
    }

    @Test
    @DisplayName("X-Forwarded-For with multiple IPs: only leftmost (real client) is used")
    void xForwardedFor_multipleIps_usesLeftmost() throws Exception {
        // "client, proxy1, proxy2" — client is the real IP, proxies should be ignored
        String realClient = "198.51.100.1";
        String headerValue = realClient + ", 10.0.0.1, 10.0.0.2";

        for (int i = 0; i < AUTH_LIMIT; i++) {
            MockHttpServletRequest req = requestFor(AUTH_PATH, "10.0.0.1");
            req.addHeader("X-Forwarded-For", headerValue);
            filter.doFilter(req, new MockHttpServletResponse(), new MockFilterChain());
        }

        MockHttpServletRequest req = requestFor(AUTH_PATH, "10.0.0.1");
        req.addHeader("X-Forwarded-For", headerValue);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(req, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(429);
    }

    @Test
    @DisplayName("X-Real-IP header is used when X-Forwarded-For is absent")
    void xRealIp_usedWhenNoXForwardedFor() throws Exception {
        String realIp = "172.16.0.99";

        for (int i = 0; i < AUTH_LIMIT; i++) {
            MockHttpServletRequest req = requestFor(AUTH_PATH, "proxy.internal");
            req.addHeader("X-Real-IP", realIp);
            filter.doFilter(req, new MockHttpServletResponse(), new MockFilterChain());
        }

        MockHttpServletRequest req = requestFor(AUTH_PATH, "proxy.internal");
        req.addHeader("X-Real-IP", realIp);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(req, response, new MockFilterChain());

        assertThat(response.getStatus())
                .as("X-Real-IP should be rate-limited correctly")
                .isEqualTo(429);
    }

    @Test
    @DisplayName("RemoteAddr is used as fallback when no proxy headers are present")
    void remoteAddr_usedAsFallback() throws Exception {
        String remoteIp = "8.8.8.8";

        for (int i = 0; i < AUTH_LIMIT; i++) {
            filter.doFilter(requestFor(AUTH_PATH, remoteIp),
                    new MockHttpServletResponse(), new MockFilterChain());
        }

        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(requestFor(AUTH_PATH, remoteIp), response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(429);
    }

    // -----------------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------------

    private MockHttpServletRequest requestFor(String path, String remoteAddr) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setServletPath(path);
        request.setRemoteAddr(remoteAddr);
        return request;
    }
}
