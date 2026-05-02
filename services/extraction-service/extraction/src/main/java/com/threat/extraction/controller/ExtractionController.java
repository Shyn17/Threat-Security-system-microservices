package com.threat.extraction.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * ExtractionController
 *
 * Minimal REST interface for the Extraction Service.
 * The service is primarily a Kafka consumer/producer, but exposes a
 * health endpoint so the API Gateway and frontend can verify liveness.
 *
 *   GET /api/v1/extract/health  – liveness probe
 */
@RestController
@RequestMapping("/api/v1/extract")
@CrossOrigin(origins = "*")
public class ExtractionController {

    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of(
                "service", "extraction-service",
                "status",  "UP",
                "role",    "Kafka consumer/producer – raw-threat-data → extracted-iocs"
        ));
    }
}
