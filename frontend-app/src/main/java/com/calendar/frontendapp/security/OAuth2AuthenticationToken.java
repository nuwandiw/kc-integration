package com.calendar.frontendapp.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Custom OAuth2 Authentication Token that holds user information
 * and the associated access token for authenticated requests.
 */
public class OAuth2AuthenticationToken implements Authentication {

    private final String name;
    private final String accessToken;
    private final String tokenType;
    private final Collection<? extends GrantedAuthority> authorities;
    private boolean authenticated;

    public OAuth2AuthenticationToken(String name, String accessToken, String tokenType,
                                     Collection<? extends GrantedAuthority> authorities) {
        this.name = name;
        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.authorities = authorities;
        this.authenticated = true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public Object getCredentials() {
        return accessToken;
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return name;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.authenticated = isAuthenticated;
    }

    @Override
    public String getName() {
        return name;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getTokenType() {
        return tokenType;
    }
}
