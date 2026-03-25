package com.app.security.ratelimiter;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for the sliding-window rate limiter.
 * No Spring context required.
 */
@DisplayName("SimpleRateLimiter — sliding window logic")
class SimpleRateLimiterTest {

    @Test
    @DisplayName("Allows exactly maxRequests within the window")
    void allowsRequestsUpToMax() {
        int max = 5;
        SimpleRateLimiter limiter = new SimpleRateLimiter(max, 60_000);

        for (int i = 0; i < max; i++) {
            assertThat(limiter.allowRequest())
                    .as("request %d should be allowed", i + 1)
                    .isTrue();
        }
    }

    @Test
    @DisplayName("Blocks the (maxRequests+1)th request within the same window")
    void blocksRequestBeyondMax() {
        SimpleRateLimiter limiter = new SimpleRateLimiter(3, 60_000);

        limiter.allowRequest(); // 1
        limiter.allowRequest(); // 2
        limiter.allowRequest(); // 3 — at limit

        assertThat(limiter.allowRequest()).as("4th request must be blocked").isFalse();
    }

    @Test
    @DisplayName("Subsequent calls after block also return false")
    void remainsBlockedForDurationOfWindow() {
        SimpleRateLimiter limiter = new SimpleRateLimiter(1, 60_000);
        limiter.allowRequest(); // consumes the only slot

        assertThat(limiter.allowRequest()).isFalse();
        assertThat(limiter.allowRequest()).isFalse();
    }

    @Test
    @DisplayName("Window resets after interval: requests are allowed again")
    void windowResetsAfterInterval() throws InterruptedException {
        // Use a very short window (100ms) so the test completes quickly
        SimpleRateLimiter limiter = new SimpleRateLimiter(1, 100);
        limiter.allowRequest(); // consumes slot
        assertThat(limiter.allowRequest()).isFalse(); // blocked

        Thread.sleep(150); // wait for window to expire

        assertThat(limiter.allowRequest()).as("should be allowed after window reset").isTrue();
    }

    @Test
    @DisplayName("getRetryAfterMillis returns positive value when blocked")
    void retryAfterMillis_isPositiveWhenBlocked() {
        SimpleRateLimiter limiter = new SimpleRateLimiter(1, 60_000);
        limiter.allowRequest(); // consume slot

        long retryAfter = limiter.getRetryAfterMillis();
        assertThat(retryAfter).isPositive();
        assertThat(retryAfter).isLessThanOrEqualTo(60_000);
    }

    @Test
    @DisplayName("getRetryAfterMillis is at most intervalMillis immediately after window reset")
    void retryAfterMillis_isWithinWindowAfterReset() throws InterruptedException {
        long intervalMillis = 500L;
        SimpleRateLimiter limiter = new SimpleRateLimiter(1, intervalMillis);
        limiter.allowRequest(); // consumes the slot — window is now fresh

        // retryAfter must be <= the window size (a new window was just started)
        assertThat(limiter.getRetryAfterMillis()).isLessThanOrEqualTo(intervalMillis);
    }
}
