package com.calendar.frontendapp.security.oauth2;

import org.springframework.web.reactive.function.client.ClientResponse;
import reactor.core.publisher.Mono;

import java.util.function.Function;

public class ClientErrorResponseHandler implements Function<ClientResponse, Mono<ClientResponse>> {

    @Override
    public Mono<ClientResponse> apply(ClientResponse response) {
        if (response.statusCode().is4xxClientError()) {
            return response.createException()
                    .flatMap(ex ->
                            Mono.error(new RuntimeException("Client error during oauth2 flow: " + ex.getMessage())));
        } else if (response.statusCode().is5xxServerError()) {
            return response.createException()
                    .flatMap(ex ->
                            Mono.error(new RuntimeException("Server error during oauth2 flow: " + ex.getMessage())));
        } else {
            return Mono.just(response);
        }
    }
}
