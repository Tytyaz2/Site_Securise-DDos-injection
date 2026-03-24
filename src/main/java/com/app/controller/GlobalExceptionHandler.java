package com.app.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.ui.Model;

/**
 * Global exception handler — ensures stack traces and internal error details
 * are never returned to the client.
 *
 * SECURITY: All exceptions are logged server-side with full detail; clients
 * only receive a generic, non-revealing error message via the error template.
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /**
     * Handle Spring Security access-denied errors (403).
     * These are logged at WARN since they may indicate probing/attack behaviour.
     */
    @ExceptionHandler(AccessDeniedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public String handleAccessDenied(AccessDeniedException ex,
                                     HttpServletRequest request,
                                     Model model) {
        log.warn("Access denied: method={} uri={}", request.getMethod(), request.getRequestURI());
        model.addAttribute("statusCode", 403);
        model.addAttribute("errorMessage", "Accès refusé.");
        return "error";
    }

    /**
     * Catch-all for unexpected runtime exceptions (500).
     * Full stack trace is logged server-side; client sees only a generic message.
     */
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public String handleGenericException(Exception ex,
                                          HttpServletRequest request,
                                          Model model) {
        log.error("Unhandled exception: method={} uri={} exception={}",
                request.getMethod(), request.getRequestURI(), ex.getMessage(), ex);
        model.addAttribute("statusCode", 500);
        model.addAttribute("errorMessage",
                "Une erreur interne s'est produite. Veuillez réessayer plus tard.");
        return "error";
    }
}
