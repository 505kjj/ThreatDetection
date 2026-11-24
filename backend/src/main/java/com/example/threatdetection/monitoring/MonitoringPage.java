package com.example.threatdetection.monitoring;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class MonitoringPage {
    @GetMapping("/monitor")
    ResponseEntity<Resource> page() { return asset("index.html", "text/html"); }

    @GetMapping("/monitor.css")
    ResponseEntity<Resource> css() { return asset("monitor.css", "text/css"); }

    @GetMapping("/monitor.js")
    ResponseEntity<Resource> script() { return asset("monitor.js", "text/javascript"); }

    @GetMapping("/api/threat/monitoring/research-summary")
    ResponseEntity<Resource> research() { return asset("research.json", "application/json"); }

    private ResponseEntity<Resource> asset(String filename, String contentType) {
        return ResponseEntity.ok().contentType(MediaType.parseMediaType(contentType))
                .header("Content-Security-Policy",
                        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                                + "frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
                .header("Referrer-Policy", "no-referrer")
                .body(new ClassPathResource("monitoring/" + filename));
    }
}
