package com.app.security.service;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.session.jdbc.config.annotation.web.http.EnableJdbcHttpSession;

@Configuration
@Profile("!test")   // disabled in test profile — tests use default HTTP session
@EnableJdbcHttpSession
public class SessionConfig {
    // Aucune configuration supplémentaire nécessaire
}