package com.calendar.frontendapp.security.oauth2;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.web.reactive.function.client.ExchangeFilterFunction.ofResponseProcessor;

@Configuration
public class OAuth2ClientConfig {

    @Value("${spring.oauth2.client.id}")
    private String clientId;

    @Value("${spring.oauth2.client.redirect-uri}")
    private String redirectUri;

    @Value("${spring.oauth2.client.scope}")
    private String scope;

    @Value("${spring.oauth2.client.authorization-uri}")
    private String authorizationUri;

    @Value("${spring.oauth2.client.token-uri}")
    private String tokenUri;

    private WebClient webClient() {
        return WebClient.builder()
                .filter(ofResponseProcessor(new ClientErrorResponseHandler()))
                .build();
    }

    private OAuth2Properties oAuth2Properties() {
        return OAuth2Properties.builder()
                .clientId(clientId)
                .redirectUri(redirectUri)
                .scope(scope)
                .authorizationUri(authorizationUri)
                .tokenUri(tokenUri)
                .build();
    }

    @Bean
    public OAuth2Client oAuth2Client() {
        return new OAuth2Client(oAuth2Properties(), webClient());
    }
}
