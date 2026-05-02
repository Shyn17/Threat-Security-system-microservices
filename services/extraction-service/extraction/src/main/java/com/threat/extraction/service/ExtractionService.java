package com.threat.extraction.service;

import com.fasterxml.jackson.databind.*;
import com.threat.extraction.model.IocEvent;
import com.threat.extraction.producer.ExtractedIocProducer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * ExtractionService
 *
 * Parses the raw JSON payloads arriving from the Kafka topic "raw-threat-data"
 * and extracts Indicators of Compromise (IOCs):
 *   • IP addresses  (type = "IP")
 *   • Domain names  (type = "DOMAIN")
 *
 * Supports two source formats:
 *   1. AbuseIPDB  – payload.data[].ipAddress / domain
 *   2. AlienVault – payload.results[].indicator (type ip/domain)
 *
 * Each extracted IOC is then forwarded as an IocEvent to the Kafka
 * topic "extracted-iocs" via ExtractedIocProducer.
 */
@Service
public class ExtractionService {

    private static final Logger log = LoggerFactory.getLogger(ExtractionService.class);

    private final ExtractedIocProducer producer;
    private final ObjectMapper mapper = new ObjectMapper();

    public ExtractionService(ExtractedIocProducer producer) {
        this.producer = producer;
    }

    public void extractAndPublish(String message) {
        try {
            JsonNode root = mapper.readTree(message);

            // Determine source tag
            String source = root.has("source") ? root.get("source").asText() : "UNKNOWN";
            JsonNode payload = root.has("payload") ? root.get("payload") : root;

            switch (source) {
                case "ABUSEIPDB" -> extractAbuseIPDB(payload);
                case "ALIENVAULT" -> extractAlienVault(payload);
                default -> extractGeneric(payload, source);
            }

        } catch (Exception e) {
            log.error("Failed to parse message: {}", e.getMessage());
        }
    }

    // -------------------------------------------------------
    //  AbuseIPDB format:
    //  { "data": [ { "ipAddress": "...", "domain": "..." }, ... ] }
    // -------------------------------------------------------
    private void extractAbuseIPDB(JsonNode payload) {
        JsonNode dataArray = payload.get("data");
        if (dataArray == null || !dataArray.isArray()) return;

        for (JsonNode node : dataArray) {
            if (node.has("ipAddress") && !node.get("ipAddress").asText().isBlank()) {
                String ip = node.get("ipAddress").asText().trim();
                if (isValidIp(ip)) {
                    IocEvent event = new IocEvent(ip, "IP", "AbuseIPDB");
                    producer.send(event);
                    log.debug("Extracted IP [AbuseIPDB]: {}", ip);
                }
            }
            if (node.has("domain") && !node.get("domain").asText().isBlank()
                    && !node.get("domain").asText().equals("null")) {
                String domain = node.get("domain").asText().trim();
                if (isValidDomain(domain)) {
                    IocEvent event = new IocEvent(domain, "DOMAIN", "AbuseIPDB");
                    producer.send(event);
                    log.debug("Extracted DOMAIN [AbuseIPDB]: {}", domain);
                }
            }
        }
    }

    // -------------------------------------------------------
    //  AlienVault OTX format:
    //  { "results": [ { "indicator": "...", "type": "IPv4|domain|hostname", ... } ] }
    // -------------------------------------------------------
    private void extractAlienVault(JsonNode payload) {
        JsonNode results = payload.get("results");
        if (results == null || !results.isArray()) return;

        for (JsonNode node : results) {
            String indicator = node.has("indicator") ? node.get("indicator").asText().trim() : "";
            String type      = node.has("type")      ? node.get("type").asText().toLowerCase() : "";

            if (indicator.isBlank()) continue;

            if (type.contains("ipv4") || type.contains("ip")) {
                if (isValidIp(indicator)) {
                    IocEvent event = new IocEvent(indicator, "IP", "AlienVault");
                    producer.send(event);
                    log.debug("Extracted IP [AlienVault]: {}", indicator);
                }
            } else if (type.contains("domain") || type.contains("hostname") || type.contains("url")) {
                if (isValidDomain(indicator)) {
                    IocEvent event = new IocEvent(indicator, "DOMAIN", "AlienVault");
                    producer.send(event);
                    log.debug("Extracted DOMAIN [AlienVault]: {}", indicator);
                }
            }
        }
    }

    // -------------------------------------------------------
    //  Fallback: generic extraction for unknown sources
    // -------------------------------------------------------
    private void extractGeneric(JsonNode payload, String source) {
        JsonNode dataArray = payload.isArray() ? payload : payload.get("data");
        if (dataArray == null) return;

        for (JsonNode node : dataArray) {
            // Try common IP field names
            for (String ipField : new String[]{"ipAddress", "ip", "indicator"}) {
                if (node.has(ipField)) {
                    String val = node.get(ipField).asText().trim();
                    if (isValidIp(val)) {
                        producer.send(new IocEvent(val, "IP", source));
                        log.debug("Extracted IP [{}]: {}", source, val);
                    }
                }
            }
            // Try common domain field names
            for (String domainField : new String[]{"domain", "hostname", "host"}) {
                if (node.has(domainField)) {
                    String val = node.get(domainField).asText().trim();
                    if (isValidDomain(val)) {
                        producer.send(new IocEvent(val, "DOMAIN", source));
                        log.debug("Extracted DOMAIN [{}]: {}", source, val);
                    }
                }
            }
        }
    }

    // -------------------------------------------------------
    //  Simple validation helpers
    // -------------------------------------------------------
    private boolean isValidIp(String ip) {
        // Basic IPv4 regex
        return ip.matches("^(\\d{1,3}\\.){3}\\d{1,3}$");
    }

    private boolean isValidDomain(String domain) {
        return domain.matches("^[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z]{2,})+$");
    }
}