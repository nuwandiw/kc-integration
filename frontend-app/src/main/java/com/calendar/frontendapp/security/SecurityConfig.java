package com.calendar.frontendapp.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Value("${spring.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    @Value("${frontend.authorization.role:#{null}}")
    private String checkedRole;

    @Value("${rest.calendar.authorization.claim:acr}")
    private String calendarAuthClaim;

    @Value("${rest.calendar.authorization.value:gold}")
    private String calendarAuthValue;

    @Bean
    public SessionAuthenticationFilter sessionAuthenticationFilter(ReactiveJwtDecoder reactiveJwtDecoder) {
        return new SessionAuthenticationFilter(frontEndJwtDecoder(), checkedRole);
    }

    @Bean
    @Order(1)
    public SecurityWebFilterChain apiSecurityFilterChain(ServerHttpSecurity http) throws Exception {
        http
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/api/**").authenticated()
                        .anyExchange().permitAll()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(Customizer.withDefaults())
                )
                .csrf(csrf -> csrf.disable());
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http,
                                                         SessionAuthenticationFilter sessionAuthenticationFilter) {
        http
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/", "/login", "/oauth2/authorize", "/oauth2/callback").permitAll()
                        .anyExchange().authenticated()
                )
                .addFilterBefore(sessionAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION);

        return http.build();
    }

    @Bean
    public ReactiveJwtDecoder restApiJwtDecoder() {
        ReactiveJwtDecoder decoder = ReactiveJwtDecoders.fromIssuerLocation(issuerUri);

        OAuth2TokenValidator<Jwt> defaultValidator = JwtValidators.createDefaultWithIssuer(issuerUri);
        OAuth2TokenValidator<Jwt> customValidator = new CustomClaimValidator(calendarAuthClaim, calendarAuthValue);
        OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(defaultValidator, customValidator);

        if (decoder instanceof NimbusReactiveJwtDecoder nimbus) {
            nimbus.setJwtValidator(validator);
        }
        return decoder;
    }

    private ReactiveJwtDecoder frontEndJwtDecoder() {
        return ReactiveJwtDecoders.fromIssuerLocation(issuerUri);
    }
}
