package com.calendar.frontendapp.security.oauth2.dpop;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class DPoPConfig {

    @Bean
    public DPoPService dPoPService() {
        return new DPoPService();
    }
}
