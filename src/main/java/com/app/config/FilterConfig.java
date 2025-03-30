// File: src/main/java/com/app/config/FilterConfig.java
package com.app.config;

import com.app.security.filter.RateLimitingFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<RateLimitingFilter> rateLimitingFilter() {
        FilterRegistrationBean<RateLimitingFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new RateLimitingFilter());
        registrationBean.addUrlPatterns("/*"); // Appliquer à toutes les routes
        registrationBean.setOrder(1); // Priorité d'exécution du filtre
        return registrationBean;
    }
}
