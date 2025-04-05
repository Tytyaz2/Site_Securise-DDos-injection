// File: src/main/java/com/app/security/filter/RateLimitingFilter.java
package com.app.security.filter;

import com.app.security.ratelimiter.SimpleRateLimiter;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class RateLimitingFilter implements Filter {

    private static final int MAX_REQUESTS_PER_MINUTE = 25;
    private static final long INTERVAL_MILLIS = 60_000; // 1 minute
    private static final long CLEANUP_INTERVAL_MILLIS = 5 * 60_000; // 5 minutes

    private final Map<String, SimpleRateLimiter> ipRateLimiters = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    public RateLimitingFilter() {
        Runnable cleanupTask = () -> ipRateLimiters.clear();
        scheduler.execute(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Thread.sleep(CLEANUP_INTERVAL_MILLIS);
                    cleanupTask.run();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        });
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        String clientIp = ((HttpServletRequest) request).getRemoteAddr();
        SimpleRateLimiter limiter = ipRateLimiters.computeIfAbsent(clientIp,
                ip -> new SimpleRateLimiter(MAX_REQUESTS_PER_MINUTE, INTERVAL_MILLIS));

        if (!limiter.allowRequest()) {
            ((HttpServletResponse) response).setStatus(429);
            long retryAfterSeconds = (limiter.getRetryAfterMillis() + 999) / 1000; // arrondi vers le haut
            ((HttpServletResponse) response).setHeader("Retry-After", String.valueOf(retryAfterSeconds));// HTTP 429 Too Many Requests
            response.getWriter().write("Rate limit exceeded. Try again later.");
            return;
        }

        chain.doFilter(request, response);
    }

    @Override
    public void init(FilterConfig filterConfig) {}

    @Override
    public void destroy() {
        scheduler.shutdownNow();
    }
}
