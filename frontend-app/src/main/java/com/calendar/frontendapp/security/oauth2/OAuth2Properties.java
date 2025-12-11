package com.calendar.frontendapp.security.oauth2;

public class OAuth2Properties {

    private String clientId;
    private String redirectUri;
    private String scope;
    private String authorizationUri;
    private String tokenUri;
    private String clientSecret;

    private OAuth2Properties(Builder builder) {
        this.clientId = builder.clientId;
        this.redirectUri = builder.redirectUri;
        this.scope = builder.scope;
        this.authorizationUri = builder.authorizationUri;
        this.tokenUri = builder.tokenUri;
        this.clientSecret = builder.clientSecret;
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getClientId() {
        return clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getScope() {
        return scope;
    }

    public String getAuthorizationUri() {
        return authorizationUri;
    }

    public String getTokenUri() {
        return tokenUri;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public static class Builder {
        private String clientId;
        private String redirectUri;
        private String scope;
        private String authorizationUri;
        private String tokenUri;
        private String clientSecret;

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }

        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }

        public Builder authorizationUri(String authorizationUri) {
            this.authorizationUri = authorizationUri;
            return this;
        }

        public Builder tokenUri(String tokenUri) {
            this.tokenUri = tokenUri;
            return this;
        }

        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        public OAuth2Properties build() {
            return new OAuth2Properties(this);
        }
    }
}

