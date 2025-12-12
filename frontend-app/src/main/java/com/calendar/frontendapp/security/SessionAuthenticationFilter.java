package com.calendar.frontendapp.security;

import org.apache.logging.log4j.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class SessionAuthenticationFilter implements WebFilter {

    private static final Logger logger = LoggerFactory.getLogger(SessionAuthenticationFilter.class);

    private final ReactiveJwtDecoder reactiveJwtDecoder;

    private String checkedRole;

    public SessionAuthenticationFilter(ReactiveJwtDecoder reactiveJwtDecoder, String checkedRole) {
        this.reactiveJwtDecoder = reactiveJwtDecoder;
        this.checkedRole = checkedRole;
    }

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

                    if (accessToken != null && !accessToken.isEmpty()) {
                        // Decode the JWT and extract claims
                        return reactiveJwtDecoder.decode(accessToken)
                                .flatMap(jwt -> {
                                    String username = extractUsername(jwt);

                                    //TODO: handle role check in the authorization server
                                    List<String> roles = extractRoles(jwt);
                                    if (Strings.isNotBlank(checkedRole) && !roles.contains(checkedRole)) {
                                        logger.warn("User '{}' does not have required role '{}'", username, checkedRole);
                                        exchange.getResponse().setStatusCode(org.springframework.http.HttpStatus.FORBIDDEN);
                                        exchange.getResponse().getHeaders().setLocation(
                                                exchange.getRequest().getURI().resolve("/login")
                                        );
                                        return exchange.getResponse().setComplete();
                                    }

                                    OAuth2AuthenticationToken authToken = new OAuth2AuthenticationToken(
                                            username,
                                            accessToken,
                                            tokenType != null ? tokenType : "Bearer",
                                            java.util.Collections.emptyList()
                                    );

                                    session.getAttributes().put("username", username);
                                    SecurityContext securityContext = new SecurityContextImpl(authToken);
                                    logger.debug("Session-based authentication established for user: {}", authToken.getName());

                                    return chain.filter(exchange)
                                            .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext)));
                                })
                                .onErrorResume(ex -> {
                                    logger.error("Failed to decode JWT token: {}", ex.getMessage());
                                    logger.debug("Token decode error details", ex);
                                    exchange.getResponse().setStatusCode(org.springframework.http.HttpStatus.UNAUTHORIZED);
                                    return exchange.getResponse().setComplete();
                                });
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

    private String extractUsername(Jwt jwt) {
        String name = jwt.getClaimAsString("name");
        if (name != null && !name.isEmpty()) {
            return name;
        }

        String preferredUsername = jwt.getClaimAsString("preferred_username");
        if (preferredUsername != null && !preferredUsername.isEmpty()) {
            return preferredUsername;
        }

        String subject = jwt.getClaimAsString("sub");
        return subject != null ? subject : "anonymous-user";
    }

    @SuppressWarnings("unchecked")
    private List<String> extractRoles(Jwt jwt) {
        List<String> roles = new ArrayList<>();

        try {
            Map<String, Object> resourceAccess = jwt.getClaimAsMap("resource_access");
            if (resourceAccess != null) {
                Map<String, Object> frontendApp = (Map<String, Object>) resourceAccess.get("frontend-app");
                if (frontendApp != null) {
                    Object rolesObj = frontendApp.get("roles");
                    if (rolesObj instanceof List) {
                        roles = (List<String>) rolesObj;
                        logger.debug("Extracted frontend-app roles: {}", roles);
                    }
                }
            }
        } catch (ClassCastException | NullPointerException ex) {
            logger.warn("Failed to extract roles from resource_access.frontend-app.roles: {}", ex.getMessage());
        }

        return roles;
    }
}
