// File: src/main/java/com/app/security/ratelimiter/SimpleRateLimiter.java
package com.app.security.ratelimiter;

public class SimpleRateLimiter {
    private final long maxRequests;
    private final long intervalMillis;
    private long nextAllowedTime;
    private long currentRequests;

    public SimpleRateLimiter(long maxRequests, long intervalMillis) {
        this.maxRequests = maxRequests;
        this.intervalMillis = intervalMillis;
        this.nextAllowedTime = System.currentTimeMillis();
        this.currentRequests = 0;
    }

    public synchronized boolean allowRequest() {
        long now = System.currentTimeMillis();
        if (now > nextAllowedTime) {
            currentRequests = 1;
            nextAllowedTime = now + intervalMillis;
            return true;
        } else {
            if (currentRequests < maxRequests) {
                currentRequests++;
                return true;
            }
            return false;
        }
    }
}
