package com.baimurzin.itlabel.core.security.config;

import org.springframework.boot.web.server.ConfigurableWebServerFactory;
import org.springframework.boot.web.server.ErrorPage;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;

@Configuration
public class ErrorPageServletCustomizer {

    @Bean
    public WebServerFactoryCustomizer<ConfigurableWebServerFactory> customizer() {
        return container -> {
            container.addErrorPages(new ErrorPage(HttpStatus.UNAUTHORIZED, "/unauthenticated"));
        };
    }
}
