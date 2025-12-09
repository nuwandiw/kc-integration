package com.calendar.frontendapp.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Service for fetching user information from the OAuth2 resource server.
 * Uses the access token to authenticate requests to the user info endpoint.
 */
@Service
public class UserInfoService {

    private static final Logger logger = LoggerFactory.getLogger(UserInfoService.class);

    private final WebClient webClient;

    public UserInfoService(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.build();
    }

    /**
     * Fetches user information from the OAuth2 resource server using the provided access token.
     * The access token is passed in the Authorization header as a Bearer token.
     *
     * @param userInfoEndpoint the user info endpoint URL
     * @param accessToken the OAuth2 access token
     * @return Mono containing user information as a map
     */
    public Mono<Map<String, Object>> getUserInfo(String userInfoEndpoint, String accessToken) {
        logger.debug("Fetching user info from: {}", userInfoEndpoint);

        return webClient.get()
                .uri(userInfoEndpoint)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .retrieve()
                .onStatus(status -> !status.is2xxSuccessful(),
                        response -> response.bodyToMono(String.class)
                                .flatMap(body -> {
                                    logger.error("Failed to fetch user info with status: {}", response.statusCode());
                                    return Mono.error(new RuntimeException("Failed to fetch user info with status: " +
                                            response.statusCode() + ", body: " + body));
                                }))
                .bodyToMono(new org.springframework.core.ParameterizedTypeReference<Map<String, Object>>() {})
                .doOnSuccess(response -> logger.info("Successfully fetched user information"))
                .doOnError(error -> logger.error("Error fetching user info", error));
    }
}
