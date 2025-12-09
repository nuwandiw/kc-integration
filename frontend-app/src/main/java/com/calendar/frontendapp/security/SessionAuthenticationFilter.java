package com.calendar.frontendapp.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.URI;

/**
 * WebFilter for extracting and validating OAuth2 access tokens from the session.
 * If an access token is found in the session, it creates an OAuth2AuthenticationToken
 * and establishes it in the SecurityContext for the request.
 */
public class SessionAuthenticationFilter implements WebFilter {

    private static final Logger logger = LoggerFactory.getLogger(SessionAuthenticationFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        if (path.equals("/") || path.equals("/login") || path.equals("/oauth2/callback")) {
            return chain.filter(exchange);
        }
        return exchange.getSession()
                .flatMap(session -> {
                    String accessToken = (String) session.getAttributes().get("access_token");
                    String tokenType = (String) session.getAttributes().get("token_type");
                    String username = (String) session.getAttributes().get("username");

                    if (accessToken != null && !accessToken.isEmpty()) {
                        logger.debug("Found access token in session for user: {}", username != null ? username : "unknown");

                        // Create custom OAuth2 authentication token
                        OAuth2AuthenticationToken authToken = new OAuth2AuthenticationToken(
                                username != null ? username : "anonymous-user",
                                accessToken,
                                tokenType != null ? tokenType : "Bearer",
                                java.util.Collections.emptyList()
                        );

                        // Create SecurityContext with the authentication token
                        SecurityContext securityContext = new SecurityContextImpl(authToken);

                        logger.debug("Session-based authentication established for user: {}", authToken.getName());

                        return chain.filter(exchange)
                                .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext)));
                    }
                    logger.info("No access token found in session");
                    exchange.getResponse().setStatusCode(HttpStatus.FOUND);
                    exchange.getResponse().getHeaders().setLocation(URI.create("/login"));
                    return Mono.empty();
                });
    }
}
