package com.calendar.frontendapp.security.oauth2;

import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;

import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames.CLIENT_ID;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CLIENT_SECRET;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CODE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.GRANT_TYPE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.REDIRECT_URI;
import static org.springframework.security.oauth2.core.endpoint.PkceParameterNames.CODE_VERIFIER;

public class OAuth2AccessTokenRequest {

    private LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
    private LinkedMultiValueMap<String, String> headers = new LinkedMultiValueMap<>();

    public OAuth2AccessTokenRequest() {
        this.headers.add(CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        this.headers.add(ACCEPT, MediaType.APPLICATION_JSON_VALUE);
    }

    public OAuth2AccessTokenRequest withHeader(String name, String value) {
        this.headers.add(name, value);
        return this;
    }

    public LinkedMultiValueMap<String, String> getBody() {
        return formData;
    }

    public LinkedMultiValueMap<String, String> getHttpHeaders() {
        return headers;
    }

    public OAuth2AccessTokenRequest from(OAuth2Properties properties, String code, String codeVerifier) {
        formData.add(GRANT_TYPE, "authorization_code");
        formData.add(CODE, code);
        formData.add(CLIENT_ID, properties.getClientId());
        if (properties.getClientSecret() != null) {
            formData.add(CLIENT_SECRET, properties.getClientSecret());
        }
        formData.add(REDIRECT_URI, properties.getRedirectUri());
        formData.add(CODE_VERIFIER, codeVerifier);
        return this;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("OAuth2AccessTokenRequest{");
        formData.forEach((key, values) -> {
            sb.append(key).append("=").append(values).append(", ");
        });
        if (!formData.isEmpty()) {
            sb.setLength(sb.length() - 2);
        }
        return sb.append("}").toString();
    }
}
