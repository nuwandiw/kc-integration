package com.calendar.frontendapp.security.oauth2;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;


import static com.calendar.frontendapp.security.oauth2.OAuthUtil.buildAuthorizationUrl;
import static com.calendar.frontendapp.security.oauth2.OAuthUtil.generateCodeChallenge;
import static com.calendar.frontendapp.security.oauth2.OAuthUtil.generateCodeVerifier;
import static com.calendar.frontendapp.security.oauth2.OAuthUtil.generateState;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CLIENT_ID;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CLIENT_SECRET;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CODE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.GRANT_TYPE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.REDIRECT_URI;

public class OAuth2Client {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2Client.class);

    private OAuth2Properties properties;
    private WebClient webClient;

    public OAuth2Client(OAuth2Properties properties, WebClient webClient) {
        this.properties = properties;
        this.webClient = webClient;
    }

    public String authorizationUrl(WebSession session) {
        String state = generateState();
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(codeVerifier);

        // Store state and code_verifier in session for later validation
        session.getAttributes().put("oauth_state", state);
        session.getAttributes().put("code_verifier", codeVerifier);

        return buildAuthorizationUrl(
                properties.getAuthorizationUri(),
                properties.getClientId(),
                properties.getRedirectUri(),
                properties.getScope(),
                state,
                codeChallenge
        );
    }

    public Mono<OAuth2AccessTokenResponse> tokenExchange(WebSession session, String authorizationCode) {
        String codeVerifier = (String) session.getAttribute("code_verifier");
        if (codeVerifier == null) {
            logger.error("code_verifier not found in session");
            throw new IllegalArgumentException("code_verifier not found in session");
        }

        OAuth2AccessTokenRequest tokenRequest = new OAuth2AccessTokenRequest()
                .with(GRANT_TYPE, "authorization_code")
                .with(CODE, authorizationCode)
                .with(CLIENT_ID, properties.getClientId())
                .with(CLIENT_SECRET, properties.getClientSecret())
                .with(REDIRECT_URI, properties.getRedirectUri())
                .with("permission", "Home#app-basic")
                .with("code_verifier", codeVerifier);

        logger.info("Sending token exchange request to for client {} to {}", properties.getClientId(), tokenRequest.toString());

        return webClient
                .post()
                .uri(properties.getTokenUri())
                .contentType(APPLICATION_FORM_URLENCODED)
                .accept(APPLICATION_JSON)
                .bodyValue(tokenRequest.getBody())
                .retrieve()
                .bodyToMono(OAuth2AccessTokenResponse.class)
                .onErrorStop()
                .doOnSuccess(tokenResponse -> {
                    session.getAttributes().put("access_token", tokenResponse.getAccessToken());
                    session.getAttributes().put("token_type", tokenResponse.getTokenType());
                    session.getAttributes().put("expires_in", tokenResponse.getExpiresIn());
                });
    }
}
