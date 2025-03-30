package com.app.controller;
import com.app.security.RecaptchaResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestTemplate;

@Controller
public class LoginController {
    @GetMapping("/login")
    public String login(Model model) {
        model.addAttribute("siteKey", siteKey); // injecte dans le modèle
        return "login";
    }

    @Value("${recaptcha.site-key}")
    private String siteKey;

    @Value("${recaptcha.secret-key}")
    private String recaptchaSecret;

    @Value("${recaptcha.site-key}")
    private String recaptchaSite;

    public boolean verifyCaptcha(String responseToken) {
        String url = "https://www.google.com/recaptcha/api/siteverify";
        RestTemplate rest = new RestTemplate();
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("secret", recaptchaSecret);
        body.add("response", responseToken);

        RecaptchaResponse recaptcha = rest.postForObject(url, new HttpEntity<>(body), RecaptchaResponse.class);
        return recaptcha != null && recaptcha.isSuccess();
    }

}