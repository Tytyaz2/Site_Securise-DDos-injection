package com.app.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Handles navigation to the login page.
 *
 * SECURITY: All CAPTCHA validation is performed upstream in
 * {@link com.app.security.filter.CaptchaValidationFilter} so that it cannot
 * be bypassed by routing. Spring Security handles actual credential
 * verification via {@link com.app.security.service.CustomUserDetailsService}.
 *
 * The hardcoded reCAPTCHA secret key that was previously in this class has
 * been removed; the secret is now loaded exclusively from the environment
 * variable RECAPTCHA_SECRET_KEY via application.properties.
 */
@Controller
public class LoginController {

    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
