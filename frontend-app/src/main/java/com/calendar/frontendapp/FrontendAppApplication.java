package com.calendar.frontendapp;

import com.calendar.frontendapp.security.oauth2.OAuth2ClientConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

@SpringBootApplication
@Import(OAuth2ClientConfig.class)
public class FrontendAppApplication {

    public static void main(String[] args) {
        SpringApplication.run(FrontendAppApplication.class, args);
    }

}
