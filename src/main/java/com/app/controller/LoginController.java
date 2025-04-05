// Updated: src/main/java/com/app/controller/LoginController.java

package com.app.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Map;

@Controller
public class LoginController {

    private static final String RECAPTCHA_SECRET_KEY = "6LcuUAsrAAAAADz3LpQM3RUjKdIJmDHzVzHTmwel";
    private static final String VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @PostMapping("/login")
    public String verifyCaptcha(@RequestParam("g-recaptcha-response") String captchaResponse,
                                HttpServletRequest request,
                                Model model) {

        if (!verifyCaptchaWithGoogle(captchaResponse)) {
            model.addAttribute("captchaError", "Captcha invalide");
            return "login";
        }

        // Laisser Spring Security gérer l'authentification ensuite
        return "redirect:/home";
    }

    private boolean verifyCaptchaWithGoogle(String responseToken) {
        RestTemplate restTemplate = new RestTemplate();
        MultiValueMap<String, String> requestMap = new LinkedMultiValueMap<>();
        requestMap.add("secret", RECAPTCHA_SECRET_KEY);
        requestMap.add("response", responseToken);

        ResponseEntity<Map> response = restTemplate.postForEntity(VERIFY_URL, requestMap, Map.class);
        Map body = response.getBody();

        return body != null && (Boolean) body.get("success");
    }
}
