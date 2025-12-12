package com.calendar.frontendapp.security.oauth2;

import com.calendar.frontendapp.security.oauth2.dpop.DPoPService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

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

    @Value("${spring.oauth2.client.secret}")
    private String clientSecret;

    @Value("${spring.oauth2.client.dpop:false}")
    private boolean dpopEnabled;

    @Autowired
    DPoPService dPoPService;

    @Bean
    public WebClient webClient(WebClient.Builder builder) {
        return builder.build();
    }

    private OAuth2Properties oAuth2Properties() {
        return OAuth2Properties.builder()
                .clientId(clientId)
                .redirectUri(redirectUri)
                .scope(scope)
                .authorizationUri(authorizationUri)
                .tokenUri(tokenUri)
                .clientSecret(clientSecret)
                .dpopEnabled(dpopEnabled)
                .build();
    }

    @Bean
    public OAuth2Client oAuth2Client(WebClient webClient) {
        return new OAuth2Client(oAuth2Properties(), webClient, dPoPService);
    }
}
