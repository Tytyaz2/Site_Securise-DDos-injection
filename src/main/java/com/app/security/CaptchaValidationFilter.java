package com.app.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


@Component
public class CaptchaValidationFilter extends OncePerRequestFilter {

    @Value("${recaptcha.secret-key}")
    private String recaptchaSecret;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        if ("/login".equals(request.getRequestURI())
                && "POST".equalsIgnoreCase(request.getMethod())
                && request.getUserPrincipal() == null) {

            System.out.println("Captcha filter triggered on POST /login");

            String captchaResponse = request.getParameter("g-recaptcha-response");
            System.out.println("🔍 Reçu côté backend : g-recaptcha-response = " + captchaResponse);

            if (captchaResponse == null || captchaResponse.isEmpty()) {
                System.out.println("Captcha response is missing");
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "CAPTCHA is required");
                return;
            }
            boolean valid = verifyCaptcha(captchaResponse);
            System.out.println("Captcha response valid? " + valid);

            if (!valid) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "CAPTCHA validation failed");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private boolean verifyCaptcha(String responseToken) {
        String url = "https://www.google.com/recaptcha/api/siteverify";
        RestTemplate rest = new RestTemplate();

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("secret", recaptchaSecret);
        body.add("response", responseToken);

        // Requête brute en texte
        String jsonResponse = rest.postForObject(url, new HttpEntity<>(body), String.class);
        System.out.println("=== RAW CAPTCHA RESPONSE ===");
        System.out.println(jsonResponse);

        // Optionnel : retourne false par défaut en attendant
        return false;
    }


}
