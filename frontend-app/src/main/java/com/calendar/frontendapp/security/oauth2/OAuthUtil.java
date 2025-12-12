package com.calendar.frontendapp.security.oauth2;

import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class OAuthUtil {

    private static final String CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    private static final int STATE_LENGTH = 32;
    private static final int CODE_VERIFIER_LENGTH = 64;

    public static String generateRandomString(int length) {
        SecureRandom random = new SecureRandom();
        StringBuilder result = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            result.append(CHARSET.charAt(random.nextInt(CHARSET.length())));
        }

        return result.toString();
    }

    public static String generateState() {
        return generateRandomString(STATE_LENGTH);
    }

    public static String generateCodeVerifier() {
        return generateRandomString(CODE_VERIFIER_LENGTH);
    }

    public static String generateCodeChallenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    public static String buildAuthorizationUrl(String authorizationEndpoint,
                                        String clientId,
                                        String redirectUri,
                                        String scope,
                                        String state,
                                        String codeChallenge) {
        return UriComponentsBuilder.fromHttpUrl(authorizationEndpoint)
                .queryParam("client_id", clientId)
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", redirectUri)
                .queryParam("scope", scope)
                .queryParam("state", state)
                .queryParam("code_challenge", codeChallenge)
                .queryParam("code_challenge_method", "S256")
                .build()
                .toUriString();
    }
}
