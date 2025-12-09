package com.calendar.frontendapp.security.oauth2;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.WebSession;

import static com.calendar.frontendapp.security.oauth2.OAuthUtil.buildAuthorizationUrl;
import static com.calendar.frontendapp.security.oauth2.OAuthUtil.generateCodeChallenge;
import static com.calendar.frontendapp.security.oauth2.OAuthUtil.generateCodeVerifier;
import static com.calendar.frontendapp.security.oauth2.OAuthUtil.generateState;

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
}
