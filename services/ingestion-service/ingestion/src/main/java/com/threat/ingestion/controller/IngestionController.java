package com.threat.ingestion.controller;

import com.threat.ingestion.service.IngestionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.concurrent.ExecutionException;

/**
 * IngestionController
 *
 * REST endpoints that trigger data ingestion from external threat-intelligence
 * sources and stream the raw payloads into the Kafka topic "raw-threat-data".
 *
 * Endpoints:
 *   GET /api/v1/ingest/abuseipdb   – fetch & stream AbuseIPDB blacklist
 *   GET /api/v1/ingest/alienvault  – fetch & stream AlienVault OTX data
 *   GET /api/v1/ingest/all         – fetch & stream both sources
 *   GET /api/v1/ingest/health      – liveness probe
 */
@RestController
@RequestMapping("/api/v1/ingest")
@CrossOrigin(origins = "*")
public class IngestionController {

    private static final Logger log = LoggerFactory.getLogger(IngestionController.class);

    @Autowired
    private IngestionService ingestionService;

    @Autowired
    private KafkaTemplate<String, String> kafkaTemplate;

    private static final String TOPIC = "raw-threat-data";

    // -------------------------------------------------------
    //  Ingest from AbuseIPDB
    // -------------------------------------------------------
    @GetMapping("/abuseipdb")
    public ResponseEntity<Map<String, String>> ingestAbuseIPDB() {
        log.info("Ingestion triggered: AbuseIPDB");
        String data = ingestionService.fetchAbuseIPDB();
        String tagged = "{\"source\":\"ABUSEIPDB\",\"payload\":" + data + "}";
        try {
            kafkaTemplate.send(TOPIC, "abuseipdb", tagged).get();
            log.info("AbuseIPDB payload sent to Kafka topic: {}", TOPIC);
            return ResponseEntity.ok(Map.of(
                    "status", "sent",
                    "source", "AbuseIPDB",
                    "topic",  TOPIC
            ));
        } catch (Exception ex) {
            log.error("Kafka send failed for AbuseIPDB: {}", ex.getMessage());
            return ResponseEntity.status(503).body(Map.of(
                    "status", "kafka_unavailable",
                    "source", "AbuseIPDB",
                    "error",  "Kafka broker unreachable – " + ex.getMessage()
            ));
        }
    }

    // -------------------------------------------------------
    //  Ingest from AlienVault OTX
    // -------------------------------------------------------
    @GetMapping("/alienvault")
    public ResponseEntity<Map<String, String>> ingestAlienVault() {
        log.info("Ingestion triggered: AlienVault OTX");
        String data = ingestionService.fetchAlienVault();
        String tagged = "{\"source\":\"ALIENVAULT\",\"payload\":" + data + "}";
        try {
            kafkaTemplate.send(TOPIC, "alienvault", tagged).get();
            log.info("AlienVault payload sent to Kafka topic: {}", TOPIC);
            return ResponseEntity.ok(Map.of(
                    "status", "sent",
                    "source", "AlienVault",
                    "topic",  TOPIC
            ));
        } catch (Exception ex) {
            log.error("Kafka send failed for AlienVault: {}", ex.getMessage());
            return ResponseEntity.status(503).body(Map.of(
                    "status", "kafka_unavailable",
                    "source", "AlienVault",
                    "error",  "Kafka broker unreachable – " + ex.getMessage()
            ));
        }
    }

    // -------------------------------------------------------
    //  Ingest ALL sources at once
    // -------------------------------------------------------
    @GetMapping("/all")
    public ResponseEntity<Map<String, String>> ingestAll() {
        log.info("Ingestion triggered: ALL sources");
        ResponseEntity<Map<String, String>> a = ingestAbuseIPDB();
        ResponseEntity<Map<String, String>> b = ingestAlienVault();
        boolean ok = a.getStatusCode().is2xxSuccessful() && b.getStatusCode().is2xxSuccessful();
        return ok
            ? ResponseEntity.ok(Map.of("status", "sent", "sources", "AbuseIPDB, AlienVault", "topic", TOPIC))
            : ResponseEntity.status(503).body(Map.of("status", "partial_failure", "sources", "AbuseIPDB, AlienVault", "error", "One or more Kafka sends failed"));
    }

    // -------------------------------------------------------
    //  Health check
    // -------------------------------------------------------
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of("service", "ingestion-service", "status", "UP"));
    }
}