package com.calendar.frontendapp.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Utility service for OAuth 2.0 authorization request generation.
 * Implements RFC 6749 (OAuth 2.0 Authorization Framework)
 * and RFC 7636 (Proof Key for Public Clients - PKCE)
 */
@Service
public class OAuthUtil {

    private static final String CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    private static final int STATE_LENGTH = 32;
    private static final int CODE_VERIFIER_LENGTH = 64;

    /**
     * Generates a cryptographically secure random string for use as OAuth2 state or code_verifier.
     * Characters are from the unreserved characters set per RFC 3986.
     *
     * @param length the length of the random string to generate
     * @return a random string of the specified length
     */
    public String generateRandomString(int length) {
        SecureRandom random = new SecureRandom();
        StringBuilder result = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            result.append(CHARSET.charAt(random.nextInt(CHARSET.length())));
        }

        return result.toString();
    }

    /**
     * Generates a state parameter for CSRF protection (RFC 7234).
     *
     * @return a random state value
     */
    public String generateState() {
        return generateRandomString(STATE_LENGTH);
    }

    /**
     * Generates a code verifier for PKCE (RFC 7636).
     *
     * @return a random code verifier
     */
    public String generateCodeVerifier() {
        return generateRandomString(CODE_VERIFIER_LENGTH);
    }

    /**
     * Generates a code challenge from a code verifier using S256 method (SHA-256).
     * Per RFC 7636 Section 4.2:
     * code_challenge = BASE64URL(SHA256(code_verifier))
     *
     * @param codeVerifier the code verifier
     * @return the code challenge in base64url format
     * @throws RuntimeException if SHA-256 algorithm is not available
     */
    public String generateCodeChallenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Builds an RFC 6749 compliant OAuth 2.0 authorization request URL.
     * Per RFC 6749 Section 4.1.1, the authorization request includes:
     * - REQUIRED: client_id, response_type, redirect_uri
     * - RECOMMENDED: scope, state
     * - OPTIONAL: code_challenge, code_challenge_method (PKCE)
     *
     * @param authorizationEndpoint the authorization server's endpoint
     * @param clientId the client identifier
     * @param redirectUri the redirect URI
     * @param scope the requested scope
     * @param state the state parameter for CSRF protection
     * @param codeChallenge the PKCE code challenge
     * @return the complete authorization URL
     */
    public String buildAuthorizationUrl(String authorizationEndpoint,
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

    /**
     * Builds an RFC 6749 Section 4.1.3 compliant access token request body.
     * Per RFC 6749 Section 4.1.3, the token request includes:
     * - REQUIRED: grant_type, client_id, redirect_uri, code
     * - OPTIONAL: code_verifier (RFC 7636 - PKCE)
     *
     * @param clientId the client identifier
     * @param redirectUri the redirect URI
     * @param authorizationCode the authorization code from the authorization response
     * @param codeVerifier the PKCE code verifier
     * @return a map of token request parameters
     */
    public java.util.Map<String, String> buildTokenRequestBody(String clientId,
                                                                String redirectUri,
                                                                String authorizationCode,
                                                                String codeVerifier) {
        java.util.Map<String, String> params = new java.util.HashMap<>();
        // RFC 6749 Section 4.1.3 - Required parameters
        params.put("grant_type", "authorization_code");
        params.put("client_id", clientId);
        params.put("redirect_uri", redirectUri);
        params.put("code", authorizationCode);
        // RFC 7636 - PKCE code_verifier
        params.put("code_verifier", codeVerifier);
        return params;
    }
}
