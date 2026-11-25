package com.example.threatdetection.monitoring;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/threat/monitoring")
class MonitoringController {
    private final MonitoringService service;

    MonitoringController(MonitoringService service) { this.service = service; }

    @PostMapping("/heartbeat")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void heartbeat(Authentication principal, @Valid @RequestBody Heartbeat body) {
        service.heartbeat(principal.getName(), MonitoringService.parse(MonitoringService.Protection.class, body.protection()));
    }

    @PostMapping("/events")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void event(Authentication principal, @Valid @RequestBody Event body) {
        service.record(principal.getName(), body);
    }

    @GetMapping("/dashboard")
    MonitoringService.Dashboard dashboard(@RequestParam(defaultValue = "REAL") Scope scope) {
        return service.dashboard(scope == Scope.SYNTHETIC);
    }

    @ExceptionHandler(DataAccessException.class)
    ResponseEntity<Void> storageUnavailable() {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .header("X-Threat-Monitoring-Status", "storage-unavailable").build();
    }

    enum Scope { REAL, SYNTHETIC }
    record Heartbeat(@NotNull @Pattern(regexp = "REPUTATION_AVAILABLE|REPUTATION_UNAVAILABLE") String protection) {}
    record Event(
            @NotNull @Pattern(regexp = "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}") String id,
            @NotNull @Pattern(regexp = "[A-Z_]{1,32}") String signal,
            @NotNull @Pattern(regexp = "BLOCKED|WARNED|BYPASSED") String action,
            @NotNull @Pattern(regexp = "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z") String detectedAt) {}
}
