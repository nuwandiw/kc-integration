package com.calendar.frontendapp.security.oauth2;

import com.calendar.frontendapp.security.oauth2.dpop.DPoPService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import org.springframework.web.server.WebSession;

import static com.calendar.frontendapp.security.oauth2.OAuthUtil.buildAuthorizationUrl;
import static com.calendar.frontendapp.security.oauth2.OAuthUtil.generateCodeChallenge;
import static com.calendar.frontendapp.security.oauth2.OAuthUtil.generateCodeVerifier;
import static com.calendar.frontendapp.security.oauth2.OAuthUtil.generateState;

public class OAuth2Client {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2Client.class);

    private final WebClient webClient;
    private final OAuth2Properties properties;
    private final DPoPService dPoPService;

    public OAuth2Client(OAuth2Properties properties, WebClient webClient, DPoPService dPoPService) {
        this.properties = properties;
        this.webClient = webClient;
        this.dPoPService = dPoPService;
    }

    public String authorizationUrl(WebSession session) {
        String state = generateState();
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(codeVerifier);

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
        String codeVerifier = (String) session.getAttributes().get("code_verifier");
        if (codeVerifier == null) {
            return Mono.error(new IllegalStateException("code_verifier not found in session"));
        }

        OAuth2AccessTokenRequest request =
                new OAuth2AccessTokenRequest().from(properties, authorizationCode, codeVerifier);
        if (properties.isDpopEnabled()) {
            String dpopProof = dPoPService.generateDPoP("POST", properties.getTokenUri(), null);
            request.withHeader("DPoP", dpopProof);
        }

        return webClient.post()
                .uri(properties.getTokenUri())
                .headers(httpHeaders -> httpHeaders.addAll(request.getHttpHeaders()))
                .bodyValue(request.getBody())
                .retrieve()
                .bodyToMono(OAuth2AccessTokenResponse.class)
                .doOnNext(tokenResponse -> {
                    session.getAttributes().put("access_token", tokenResponse.getAccessToken());
                    session.getAttributes().put("token_type", tokenResponse.getTokenType());
                    session.getAttributes().put("expires_in", tokenResponse.getExpiresIn());
                    logger.debug("Token exchange successful, stored tokens in session");
                })
                .onErrorStop();
    }
}
