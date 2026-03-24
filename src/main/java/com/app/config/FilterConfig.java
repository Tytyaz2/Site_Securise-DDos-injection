package com.app.config;

import com.app.security.filter.CaptchaValidationFilter;
import com.app.security.filter.RateLimitingFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    /**
     * Registers the rate-limiting filter with highest priority so it fires
     * before all other filters and can reject over-limit requests early.
     *
     * SECURITY: Applied to all URL patterns to protect against DDoS/brute-force
     * on every endpoint, not just authenticated routes.
     */
    @Bean
    public FilterRegistrationBean<RateLimitingFilter> rateLimitingFilter() {
        FilterRegistrationBean<RateLimitingFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new RateLimitingFilter());
        registrationBean.addUrlPatterns("/*");
        registrationBean.setOrder(1);
        return registrationBean;
    }

    /**
     * Prevents Spring Boot from auto-registering CaptchaValidationFilter as a
     * standalone servlet filter. It is registered exclusively via Spring Security's
     * filter chain (addFilterBefore in SecurityConfig), which is the correct place
     * for security filters — they run inside the Spring Security context and have
     * access to the SecurityContextHolder.
     *
     * Without this bean, Spring Boot would register the @Component filter a second
     * time as a plain servlet filter, causing CAPTCHA to be validated twice per
     * request and breaking request body parsing on the second pass.
     */
    @Bean
    public FilterRegistrationBean<CaptchaValidationFilter> captchaFilterRegistration(
            CaptchaValidationFilter captchaValidationFilter) {
        FilterRegistrationBean<CaptchaValidationFilter> registrationBean =
                new FilterRegistrationBean<>(captchaValidationFilter);
        // Disable auto-registration as a servlet filter; Spring Security chain handles it
        registrationBean.setEnabled(false);
        return registrationBean;
    }
}
