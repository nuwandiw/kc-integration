package com.calendar.frontendapp.controller;

import com.calendar.frontendapp.security.oauth2.OAuth2Client;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

@Controller
public class Frontend {

    private static final Logger logger = LoggerFactory.getLogger(Frontend.class);

    @Autowired
    private OAuth2Client oauth2Client;

    @GetMapping("/")
    public Mono<String> index() {
        return Mono.just("redirect:/login");
    }

    @GetMapping("/home")
    public Mono<String> home(WebSession session, Model model) {
        model.addAttribute("message", "Welcome to Home");
        model.addAttribute("username", session.getAttribute("username"));
        model.addAttribute("accessToken", (String) session.getAttributes().get("access_token"));
        return Mono.just("home");
    }

    @GetMapping("/login")
    public Mono<String> login(WebSession session, Model model) {
        return Mono.just("login");
    }

    @PostMapping("/oauth2/authorize")
    public Mono<String> authorize(WebSession session) {
        return Mono.defer(() -> {
            try {
                String authorizationUrl = oauth2Client.authorizationUrl(session);
                if (authorizationUrl != null) {
                    return Mono.just("redirect:" + authorizationUrl);
                }
                logger.error("Failed to generate authorization URL");
                return Mono.just("redirect:/login?error=authorization_failed");
            } catch (Exception ex) {
                logger.error("Authorization initiation failed: {}", ex.getMessage(), ex);
                return Mono.just("redirect:/login?error=authorization_failed");
            }
        });
    }

    @GetMapping("/oauth2/callback")
    public Mono<String> handleAuthorizationCallback(
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "error", required = false) String error,
            WebSession session,
            Model model) {
        if (error != null) {
            model.addAttribute("error", error);
            return Mono.just("login");
        }

        if (code == null || code.isEmpty()) {
            model.addAttribute("error", "Missing authorization code");
            return Mono.just("login");
        }

        if (state == null || state.isEmpty()) {
            model.addAttribute("error", "Missing state parameter");
            return Mono.just("login");
        }

        return oauth2Client.tokenExchange(session, code)
                .then(Mono.just("redirect:/home"))
                .onErrorResume(ex -> {
                    model.addAttribute("error", "Token exchange failed: " + ex.getMessage());
                    return Mono.just("login");
                });
    }

}
