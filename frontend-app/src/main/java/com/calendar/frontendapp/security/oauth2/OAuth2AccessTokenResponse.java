package com.calendar.frontendapp.security.oauth2;

import com.fasterxml.jackson.annotation.JsonProperty;

public class OAuth2AccessTokenResponse {

    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("token_type")
    private String tokenType;

    @JsonProperty("expires_in")
    private Long expiresIn;

    @JsonProperty("refresh_token")
    private String refreshToken;

    @JsonProperty("scope")
    private String scope;

    @JsonProperty("custom_parameters")
    private java.util.Map<String, Object> customParameters;

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public Long getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(Long expiresIn) {
        this.expiresIn = expiresIn;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public java.util.Map<String, Object> getCustomParameters() {
        return customParameters;
    }

    public void setCustomParameters(java.util.Map<String, Object> customParameters) {
        this.customParameters = customParameters;
    }

    public boolean isDPopBound() {
        return tokenType != null && tokenType.equalsIgnoreCase("DPoP");
    }

    public boolean isExpired(long issuedAtMillis) {
        if (expiresIn == null) {
            return false; // No expiration info available
        }
        long expirationTimeMillis = issuedAtMillis + (expiresIn * 1000);
        return System.currentTimeMillis() > expirationTimeMillis;
    }

    @Override
    public String toString() {
        return "OAuth2AccessTokenResponse{" +
                "accessToken='" + (accessToken != null ? "***" : null) + '\'' +
                ", tokenType='" + tokenType + '\'' +
                ", expiresIn=" + expiresIn +
                ", refreshToken='" + (refreshToken != null ? "***" : null) + '\'' +
                ", scope='" + scope + '\'' +
                ", customParameters=" + customParameters +
                '}';
    }
}
