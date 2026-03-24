package com.app.security.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.Map;

/**
 * Validates Google reCAPTCHA v2 tokens on POST /login and POST /register.
 *
 * SECURITY: The secret key is loaded from the environment variable
 * RECAPTCHA_SECRET_KEY (via application.properties), never hard-coded.
 */
@Component
public class CaptchaValidationFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(CaptchaValidationFilter.class);

    private static final String VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";

    // Injected via constructor; SecurityConfig passes this bean via addFilterBefore.
    // When instantiated by Spring the @Value is resolved; when newed directly it is
    // read from the system property set by FilterConfig.
    private final String secretKey;

    /**
     * Primary constructor used by Spring (via @Component / FilterConfig).
     * The secret key comes from application.properties / env var.
     */
    public CaptchaValidationFilter(@Value("${recaptcha.secret.key}") String secretKey) {
        this.secretKey = secretKey;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String method = httpRequest.getMethod();
        String path = httpRequest.getServletPath();

        // Enforce CAPTCHA on POST /login and POST /register
        boolean isSensitivePost = "POST".equalsIgnoreCase(method) &&
                ("/login".equals(path) || "/register".equals(path));

        if (isSensitivePost) {
            String captchaResponse = httpRequest.getParameter("g-recaptcha-response");

            if (captchaResponse == null || captchaResponse.isBlank()) {
                log.warn("CAPTCHA token missing on {} {}", method, path);
                httpResponse.sendRedirect(path + "?error=captcha");
                return;
            }

            if (!isCaptchaValid(captchaResponse)) {
                log.warn("CAPTCHA validation failed on {} {}", method, path);
                httpResponse.sendRedirect(path + "?error=captcha");
                return;
            }

            log.debug("CAPTCHA validated successfully for {} {}", method, path);
        }

        chain.doFilter(request, response);
    }

    private boolean isCaptchaValid(String captchaToken) {
        RestTemplate restTemplate = new RestTemplate();
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("secret", secretKey);
        params.add("response", captchaToken);

        try {
            ResponseEntity<Map> verifyResponse = restTemplate.postForEntity(VERIFY_URL, params, Map.class);
            Map<?, ?> body = verifyResponse.getBody();
            return body != null && Boolean.TRUE.equals(body.get("success"));
        } catch (Exception e) {
            // Log without exposing the token value
            log.error("reCAPTCHA verification request failed: {}", e.getMessage());
            return false;
        }
    }
}
