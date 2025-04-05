package com.app.security.ratelimiter;

public class SimpleRateLimiter {
    private final long maxRequests;
    private final long intervalMillis;
    private long windowStart;
    private long requestCount;

    public SimpleRateLimiter(long maxRequests, long intervalMillis) {
        this.maxRequests = maxRequests;
        this.intervalMillis = intervalMillis;
        this.windowStart = System.currentTimeMillis();
        this.requestCount = 0;
    }
    public synchronized long getRetryAfterMillis() {
        long now = System.currentTimeMillis();
        long windowEnd = windowStart + intervalMillis;
        return Math.max(0, windowEnd - now);
    }

    public synchronized boolean allowRequest() {
        long now = System.currentTimeMillis();

        if (now - windowStart >= intervalMillis) {
            // New window
            windowStart = now;
            requestCount = 0;
        }

        if (requestCount < maxRequests) {
            requestCount++;
            return true;
        } else {
            return false;
        }
    }
}
