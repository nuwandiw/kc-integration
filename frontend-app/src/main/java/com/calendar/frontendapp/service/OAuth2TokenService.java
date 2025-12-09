package com.calendar.frontendapp.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.BodyInserters;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Service for handling OAuth 2.0 token exchange operations.
 * Implements RFC 6749 Section 4.1.3 (Access Token Request)
 * and RFC 6749 Section 4.1.4 (Access Token Response)
 * Uses Spring WebFlux WebClient for reactive HTTP communication.
 */
@Service
public class OAuth2TokenService {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2TokenService.class);

    private final WebClient webClient;
    private final ObjectMapper objectMapper;

    public OAuth2TokenService(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.build();
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Exchanges an authorization code for an access token.
     * Per RFC 6749 Section 4.1.3, sends a POST request to the token endpoint
     * with the authorization code and PKCE code_verifier.
     * Returns a Mono for reactive non-blocking processing.
     *
     * @param tokenEndpoint the token server's endpoint
     * @param tokenRequestBody the token request body parameters
     * @return a Mono containing the token response with access_token, token_type, expires_in, etc.
     */
    public Mono<Map> exchangeCodeForToken(String tokenEndpoint,
                                          Map<String, String> tokenRequestBody) {
        logger.debug("Exchanging authorization code for access token at: {}", tokenEndpoint);

        // Create form-encoded body for token request
        StringBuilder formBody = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, String> entry : tokenRequestBody.entrySet()) {
            if (!first) {
                formBody.append("&");
            }
            formBody.append(entry.getKey()).append("=").append(encodeFormParameter(entry.getValue()));
            first = false;
        }

        // Send POST request to token endpoint using WebClient
        return webClient.post()
                .uri(tokenEndpoint)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .body(BodyInserters.fromValue(formBody.toString()))
                .retrieve()
                .onStatus(status -> !status.is2xxSuccessful(),
                        response -> response.bodyToMono(String.class)
                                .flatMap(body -> {
                                    logger.error("Token exchange failed with status: {}", response.statusCode());
                                    return Mono.error(new RuntimeException("Token exchange failed with status: " +
                                            response.statusCode() + ", body: " + body));
                                }))
                .bodyToMono(Map.class)
                .doOnSuccess(response -> logger.info("Successfully exchanged authorization code for access token"))
                .doOnError(error -> logger.error("Error during token exchange", error));
    }

    /**
     * Encodes a parameter value for form submission per application/x-www-form-urlencoded format.
     *
     * @param value the parameter value to encode
     * @return the URL-encoded parameter value
     */
    private String encodeFormParameter(String value) {
        try {
            return java.net.URLEncoder.encode(value, "UTF-8")
                    .replace("+", "%20")
                    .replace("%21", "!")
                    .replace("%27", "'")
                    .replace("%28", "(")
                    .replace("%29", ")")
                    .replace("%7E", "~");
        } catch (java.io.UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 encoding not supported", e);
        }
    }
}
