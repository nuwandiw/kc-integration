package com.calendar.frontendapp.controller;

import com.calendar.frontendapp.config.OAuth2Properties;
import com.calendar.frontendapp.service.OAuth2TokenService;
import com.calendar.frontendapp.service.OAuthUtil;
import com.calendar.frontendapp.service.UserInfoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

@Controller
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private OAuth2Properties oauth2Properties;

    @Autowired
    private OAuthUtil oauthUtil;

    @Autowired
    private OAuth2TokenService oauth2TokenService;

    @Autowired
    private UserInfoService userInfoService;

    @GetMapping("/")
    public Mono<String> index() {
        return Mono.just("redirect:/login");
    }

    @GetMapping("/home")
    public Mono<String> home(Model model) {
        model.addAttribute("message", "Welcome to Home");
        return Mono.just("home");
    }

    @GetMapping("/calendar")
    public Mono<String> calendar(Model model) {
        model.addAttribute("message", "Calendar Page");
        return Mono.just("calendar");
    }

    /**
     * Initiates RFC 6749 compliant OAuth 2.0 authorization request.
     * Generates PKCE parameters and prepares the authorization URL for redirect.
     * Reactive implementation using WebSession from ServerWebExchange.
     *
     * @param exchange the ServerWebExchange for accessing WebSession
     * @param model    the Model for view rendering
     * @return Mono with login view name and authorization URL
     */
    @GetMapping("/login")
    public Mono<String> login(ServerWebExchange exchange, Model model) {

        return exchange.getSession()
                .flatMap(session -> {
                    // Generate PKCE parameters per RFC 7636
                    String state = oauthUtil.generateState();
                    String codeVerifier = oauthUtil.generateCodeVerifier();
                    String codeChallenge = oauthUtil.generateCodeChallenge(codeVerifier);

                    // Store state and code_verifier in session for later validation
                    session.getAttributes().put("oauth_state", state);
                    session.getAttributes().put("code_verifier", codeVerifier);

                    // Build authorization URL per RFC 6749 Section 4.1.1
                    String authorizationUrl = oauthUtil.buildAuthorizationUrl(
                            oauth2Properties.getAuthorizationUri(),
                            oauth2Properties.getClientId(),
                            oauth2Properties.getRedirectUri(),
                            oauth2Properties.getScope(),
                            state,
                            codeChallenge
                    );

                    model.addAttribute("authorizationUrl", authorizationUrl);

                    return Mono.just("login");
                });
    }

    /**
     * Handles the OAuth 2.0 authorization response callback.
     * Per RFC 6749 Section 4.1.2, the authorization server redirects to this endpoint
     * with authorization code and state parameters.
     * Then exchanges the authorization code for an access token per RFC 6749 Section 4.1.3.
     * Reactive implementation using WebSession from ServerWebExchange.
     *
     * @param code     the authorization code from the authorization server
     * @param state    the state parameter for CSRF validation
     * @param error    optional error code if authorization failed
     * @param exchange the ServerWebExchange for accessing WebSession
     * @return Mono with redirect to home page on success or error page on failure
     */
    @GetMapping("/oauth2/callback")
    public Mono<String> handleAuthorizationCallback(
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "error", required = false) String error,
            ServerWebExchange exchange) {

        if (error != null) {
            return Mono.just("redirect:/login?error=" + error);
        }

        if (code == null || code.isEmpty()) {
            return Mono.just("redirect:/login?error=missing_code");
        }

        if (state == null || state.isEmpty()) {
            return Mono.just("redirect:/login?error=missing_state");
        }

        return exchange.getSession()
                .flatMap(session -> {
                    String storedState = (String) session.getAttributes().get("oauth_state");
                    if (storedState == null || !storedState.equals(state)) {
                        logger.error("State parameter mismatch - CSRF attack detected");
                        return Mono.just("redirect:/login?error=invalid_state");
                    }

                    // Retrieve code_verifier from session for PKCE validation
                    String codeVerifier = (String) session.getAttributes().get("code_verifier");
                    if (codeVerifier == null || codeVerifier.isEmpty()) {
                        logger.error("Code verifier missing from session");
                        return Mono.just("redirect:/login?error=missing_code_verifier");
                    }

                    logger.debug("Preparing token request with authorization code");

                    Map<String, String> tokenRequestBody = oauthUtil.buildTokenRequestBody(
                            oauth2Properties.getClientId(),
                            oauth2Properties.getRedirectUri(),
                            code,
                            codeVerifier
                    );

                    return oauth2TokenService.exchangeCodeForToken(
                                    oauth2Properties.getTokenUri(),
                                    tokenRequestBody)
                            .flatMap(tokenResponse -> {
                                logger.info("Successfully obtained access token from token server");

                                // Store token response in session for use in authenticated requests
                                String accessToken = (String) tokenResponse.get("access_token");
                                String tokenType = (String) tokenResponse.get("token_type");

                                session.getAttributes().put("access_token", accessToken);
                                session.getAttributes().put("token_type", tokenType);
                                session.getAttributes().put("expires_in", tokenResponse.get("expires_in"));
                                if (tokenResponse.containsKey("id_token")) {
                                    session.getAttributes().put("id_token", tokenResponse.get("id_token"));
                                }
                                session.getAttributes().put("username", "oauth-user");
                                session.getAttributes().remove("oauth_state");
                                session.getAttributes().remove("code_verifier");

                                return Mono.just("redirect:/home");
                            })
                            .onErrorResume(error_ex -> {
                                logger.error("Token exchange failed", error_ex);
                                return Mono.just("redirect:/login?error=token_exchange_failed");
                            });
                });
    }

}
