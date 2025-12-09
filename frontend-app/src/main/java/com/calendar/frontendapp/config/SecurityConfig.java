package com.calendar.frontendapp.config;

import com.calendar.frontendapp.security.SessionAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    /**
     * Registers the custom session-based authentication filter.
     * This filter extracts access tokens from the session and establishes authentication context.
     *
     * @return the configured SessionAuthenticationFilter
     */
    @Bean
    public SessionAuthenticationFilter sessionAuthenticationFilter() {
        return new SessionAuthenticationFilter();
    }

    /**
     * Configures the security filter chain for WebFlux.
     * Integrates the custom session-based authentication filter to handle OAuth2 access tokens from sessions.
     *
     * @param http the ServerHttpSecurity to configure
     * @param sessionAuthenticationFilter the custom filter for session-based authentication
     * @return the configured SecurityWebFilterChain
     * @throws Exception if configuration fails
     */
    @Bean
    public SecurityWebFilterChain filterChain(ServerHttpSecurity http,
                                              SessionAuthenticationFilter sessionAuthenticationFilter) throws Exception {
        http
            // Configure authorization rules
            .authorizeExchange((requests) ->
                requests
                    .pathMatchers("/", "/login", "/oauth2/callback").permitAll()
                    .anyExchange().authenticated()
            )
            .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
            .addFilterBefore(sessionAuthenticationFilter,
                    SecurityWebFiltersOrder.AUTHENTICATION);

        return http.build();
    }

}
