package com.calendar.frontendapp.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Reactive WebFilter for extracting and validating OAuth2 access tokens from the WebSession.
 * If an access token is found in the session, it creates an OAuth2AuthenticationToken
 * and establishes it in the SecurityContext for the request.
 */
public class SessionAuthenticationFilter implements WebFilter {

    private static final Logger logger = LoggerFactory.getLogger(SessionAuthenticationFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        // Skip filtering for public endpoints
        if (path.equals("/") || path.equals("/login") || path.startsWith("/oauth2/callback") || path.equals("/oauth2/authorize")) {
            return chain.filter(exchange);
        }

        return exchange.getSession()
                .flatMap(session -> {
                    String accessToken = (String) session.getAttributes().get("access_token");
                    String tokenType = (String) session.getAttributes().get("token_type");
                    String username = (String) session.getAttributes().get("username");

                    if (accessToken != null && !accessToken.isEmpty()) {
                        logger.debug("Found access token in session for user: {}", username != null ? username : "unknown");
                        OAuth2AuthenticationToken authToken = new OAuth2AuthenticationToken(
                                username != null ? username : "anonymous-user",
                                accessToken,
                                tokenType != null ? tokenType : "Bearer",
                                java.util.Collections.emptyList()
                        );

                        SecurityContext securityContext = new SecurityContextImpl(authToken);
                        logger.debug("Session-based authentication established for user: {}", authToken.getName());

                        return chain.filter(exchange)
                                .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext)));
                    } else {
                        logger.info("No access token found in session, redirecting to login");
                        exchange.getResponse().setStatusCode(org.springframework.http.HttpStatus.FOUND);
                        exchange.getResponse().getHeaders().setLocation(
                                exchange.getRequest().getURI().resolve("/login")
                        );
                        return exchange.getResponse().setComplete();
                    }
                });
    }
}
