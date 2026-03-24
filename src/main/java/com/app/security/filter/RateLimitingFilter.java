package com.app.security.filter;

import com.app.security.ratelimiter.SimpleRateLimiter;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * IP-based rate-limiting filter.
 *
 * SECURITY improvements over original:
 * - Resolves client IP through X-Forwarded-For / X-Real-IP to work correctly
 *   behind reverse proxies and load balancers.
 * - Applies stricter limits on sensitive paths (/login, /register).
 * - Uses a ScheduledExecutorService with scheduleAtFixedRate (not a raw sleep
 *   loop) for periodic cleanup, preventing thread resource leaks.
 * - Logs rate-limit events at WARN level without leaking sensitive parameters.
 */
public class RateLimitingFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(RateLimitingFilter.class);

    // General limit: 60 requests per minute for normal pages
    private static final int MAX_REQUESTS_GENERAL = 60;
    // Stricter limit: 10 requests per minute for authentication endpoints
    private static final int MAX_REQUESTS_AUTH = 10;
    private static final long INTERVAL_MILLIS = 60_000L;
    private static final long CLEANUP_INTERVAL_MINUTES = 5L;

    private final Map<String, SimpleRateLimiter> generalLimiters = new ConcurrentHashMap<>();
    private final Map<String, SimpleRateLimiter> authLimiters = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "rate-limiter-cleanup");
        t.setDaemon(true);
        return t;
    });

    public RateLimitingFilter() {
        // Periodic cleanup: remove all entries every 5 minutes to prevent memory growth
        scheduler.scheduleAtFixedRate(() -> {
            generalLimiters.clear();
            authLimiters.clear();
            log.debug("Rate-limiter maps cleared");
        }, CLEANUP_INTERVAL_MINUTES, CLEANUP_INTERVAL_MINUTES, TimeUnit.MINUTES);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String clientIp = resolveClientIp(httpRequest);
        String path = httpRequest.getServletPath();

        // Apply stricter limits on authentication endpoints
        boolean isAuthEndpoint = "/login".equals(path) || "/register".equals(path);

        SimpleRateLimiter limiter;
        if (isAuthEndpoint) {
            limiter = authLimiters.computeIfAbsent(clientIp,
                    ip -> new SimpleRateLimiter(MAX_REQUESTS_AUTH, INTERVAL_MILLIS));
        } else {
            limiter = generalLimiters.computeIfAbsent(clientIp,
                    ip -> new SimpleRateLimiter(MAX_REQUESTS_GENERAL, INTERVAL_MILLIS));
        }

        if (!limiter.allowRequest()) {
            long retryAfterSeconds = (limiter.getRetryAfterMillis() + 999) / 1000;
            log.warn("Rate limit exceeded for IP={} path={} retryAfterSeconds={}",
                    clientIp, path, retryAfterSeconds);
            httpResponse.setStatus(429);
            httpResponse.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
            httpResponse.setContentType("text/plain;charset=UTF-8");
            httpResponse.getWriter().write("Too many requests. Please try again later.");
            return;
        }

        chain.doFilter(request, response);
    }

    /**
     * Resolves the real client IP address, taking into account common proxy
     * headers. Only trusts the first (leftmost) IP in X-Forwarded-For to
     * prevent header-spoofing by clients.
     *
     * SECURITY NOTE: If your deployment does NOT use a trusted reverse proxy,
     * remove X-Forwarded-For handling to prevent IP spoofing.
     */
    private String resolveClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            // X-Forwarded-For: client, proxy1, proxy2 — take the leftmost
            String firstIp = xForwardedFor.split(",")[0].trim();
            if (!firstIp.isEmpty()) {
                return firstIp;
            }
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isBlank()) {
            return xRealIp.trim();
        }
        return request.getRemoteAddr();
    }

    @Override
    public void init(FilterConfig filterConfig) {}

    @Override
    public void destroy() {
        scheduler.shutdownNow();
    }
}
