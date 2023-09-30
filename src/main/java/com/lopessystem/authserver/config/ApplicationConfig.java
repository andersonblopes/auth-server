package com.lopessystem.authserver.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import java.util.List;

@Component
@Getter
@Setter
@Validated
@ConfigurationProperties("app.auth")
public class ApplicationConfig {

    @NotBlank
    private String providerUrl;

    @NotNull
    private List<String> allowedUris;
}
