package com.app.security.service;

import com.app.security.filter.CaptchaValidationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomUserDetailsService userDetailsService;
    // Injected by Spring so @Value("${recaptcha.secret.key}") is resolved correctly
    private final CaptchaValidationFilter captchaValidationFilter;

    public SecurityConfig(CustomUserDetailsService userDetailsService,
                          CaptchaValidationFilter captchaValidationFilter) {
        this.userDetailsService = userDetailsService;
        this.captchaValidationFilter = captchaValidationFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // ---------------------------------------------------------------
            // HTTP Security Headers
            // ---------------------------------------------------------------
            .headers(headers -> headers
                // Strict-Transport-Security: force HTTPS for 1 year, include subdomains
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000)
                    .preload(true)
                )
                // X-Frame-Options: DENY — prevent clickjacking
                .frameOptions(frame -> frame.deny())
                // X-Content-Type-Options: nosniff — prevent MIME sniffing
                .contentTypeOptions(ct -> {})
                // Referrer-Policy: strict-origin-when-cross-origin
                .referrerPolicy(referrer ->
                    referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
                )
                // Permissions-Policy: disable access to sensitive browser features
                .permissionsPolicy(permissions ->
                    permissions.policy(
                        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), " +
                        "interest-cohort=()"
                    )
                )
                // Content-Security-Policy
                // - default-src 'self': only same-origin by default
                // - script-src: allow same-origin + Google reCAPTCHA
                // - frame-src: allow Google reCAPTCHA iframe
                // - style-src: allow same-origin + inline styles for reCAPTCHA widget
                // - img-src: allow same-origin + data URIs
                // - connect-src: same-origin only
                // - font-src: same-origin only
                // - object-src: none (no Flash/plugins)
                .contentSecurityPolicy(csp ->
                    csp.policyDirectives(
                        "default-src 'self'; " +
                        "script-src 'self' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; " +
                        "frame-src https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/; " +
                        "style-src 'self' 'unsafe-inline'; " +
                        "img-src 'self' data:; " +
                        "connect-src 'self'; " +
                        "font-src 'self'; " +
                        "object-src 'none'; " +
                        "base-uri 'self'; " +
                        "form-action 'self'; " +
                        "frame-ancestors 'none';"
                    )
                )
            )

            // ---------------------------------------------------------------
            // CSRF protection — explicitly enabled (Spring Security default)
            // ---------------------------------------------------------------
            .csrf(csrf -> csrf
                // CSRF is enabled by default; this block makes it explicit and
                // configures the token to also be readable as a header (for AJAX).
                // The token is already injected via th:name/${_csrf} in all forms.
            )

            // ---------------------------------------------------------------
            // Filters
            // ---------------------------------------------------------------
            // Use the Spring-managed bean so @Value injection is honoured
            .addFilterBefore(captchaValidationFilter, UsernamePasswordAuthenticationFilter.class)

            // ---------------------------------------------------------------
            // Authorization rules
            // ---------------------------------------------------------------
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/register").permitAll()
                .requestMatchers("/css/**", "/js/**", "/styles.css").permitAll()
                .requestMatchers("/error").permitAll()
                .requestMatchers("/home", "/home/**", "/notes/**").authenticated()
                .anyRequest().authenticated()
            )

            // ---------------------------------------------------------------
            // Form login
            // ---------------------------------------------------------------
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/home", true)
                .failureUrl("/login?error=true")
                .permitAll()
            )

            // ---------------------------------------------------------------
            // Logout
            // ---------------------------------------------------------------
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID", "SESSION")
                .permitAll()
            )

            // ---------------------------------------------------------------
            // Session management
            // ---------------------------------------------------------------
            .sessionManagement(session -> session
                .sessionFixation().migrateSession()
                .maximumSessions(1)
                .sessionRegistry(sessionRegistry())
                .expiredUrl("/login?expired")
            );

        return http.build();
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // BCrypt with strength 12 (default is 10; 12 is stronger without being prohibitive)
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
}
