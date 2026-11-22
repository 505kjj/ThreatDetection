package com.example.threatdetection.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.Map;

@Validated
@ConfigurationProperties("threat.security")
public record ApiSecurityProperties(
        List<String> allowedOrigins,
        Map<@Pattern(regexp = "[a-z][a-z0-9-]{0,63}") String, @NotNull @Valid Client> clients) {

    public ApiSecurityProperties {
        allowedOrigins = allowedOrigins == null ? List.of() : List.copyOf(allowedOrigins);
        clients = clients == null ? Map.of() : Map.copyOf(clients);
    }

    public record Client(
            @NotNull Role role,
            @NotNull @Pattern(regexp = "[0-9a-f]{64}") String tokenSha256) {}

    public enum Role {
        ADMIN, BROWSER
    }
}
