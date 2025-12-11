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
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private OAuth2Client oauth2Client;

    @GetMapping("/")
    public String index() {
        return "redirect:/login";
    }

    @GetMapping("/home")
    public String home(WebSession session, Model model) {
        model.addAttribute("message", "Welcome to Home");
        return "home";
    }

    @GetMapping("/login")
    public String login(WebSession session, Model model) {
        model.addAttribute("session", session);
        return "login";
    }

    @PostMapping("/oauth2/authorize")
    public String authorize(WebSession session) {
        String authorizationUrl = oauth2Client.authorizationUrl(session);
        if (authorizationUrl != null) {
            return "redirect:" + authorizationUrl;
        }
        return "redirect:/login?error=authorization_failed";
    }

    /**
     * Handles the OAuth 2.0 authorization response callback.
     * Per RFC 6749 Section 4.1.2, the authorization server redirects to this endpoint
     * with authorization code and state parameters.
     * Then exchanges the authorization code for an access token per RFC 6749 Section 4.1.3.
     * Reactive implementation using WebSession from ServerWebExchange.
     */
    @GetMapping("/oauth2/callback")
    public Mono<String> handleAuthorizationCallback(
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "error", required = false) String error,
            WebSession session, Model model) {

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
                .flatMap(tokenResponse -> Mono.just("redirect:/home"))
                .onErrorResume(ex -> {
                    model.addAttribute("error", "Token exchange failed: " + ex.getMessage());
                    return Mono.just("login");
                });
    }

}
