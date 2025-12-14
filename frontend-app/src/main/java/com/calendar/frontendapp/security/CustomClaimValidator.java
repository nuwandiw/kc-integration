package com.calendar.frontendapp.security;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

public class CustomClaimValidator implements OAuth2TokenValidator<Jwt> {
    private final String claimName;
    private final String expectedValue;

    public CustomClaimValidator(String claimName, String expectedValue) {
        this.claimName = claimName;
        this.expectedValue = expectedValue;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        Object claim = jwt.getClaim(claimName);
        if (claim == null) {
            return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Missing claim: " + claimName, null));
        }
        if (!expectedValue.equals(String.valueOf(claim))) {
            return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Invalid claim value for: " + claimName, null));
        }
        return OAuth2TokenValidatorResult.success();
    }
}
