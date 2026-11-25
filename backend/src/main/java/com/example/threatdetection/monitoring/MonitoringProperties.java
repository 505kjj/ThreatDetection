package com.example.threatdetection.monitoring;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import java.util.Set;

@Validated
@ConfigurationProperties("threat.monitoring")
record MonitoringProperties(
        @DefaultValue("14") @Min(1) @Max(90) int retentionDays,
        @DefaultValue("60") @Min(1) @Max(120) int eventsPerMinute,
        Set<String> syntheticClients,
        String storePath,
        @jakarta.validation.Valid Postgres postgres) {
    record Postgres(String jdbcUrl, String username, String password, String rootCertificate,
                    boolean allowLoopbackWithoutTls, @DefaultValue("3") @Min(1) @Max(16) int poolSize) {
        @Override
        public String toString() { return "Postgres[configured]"; }
    }

    MonitoringProperties {
        syntheticClients = syntheticClients == null ? Set.of() : Set.copyOf(syntheticClients);
    }
}
