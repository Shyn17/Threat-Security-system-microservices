package com.threat.ingestion.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

/**
 * IngestionService
 * Connects to external threat-intelligence APIs (AbuseIPDB and AlienVault OTX)
 * and returns their raw JSON payloads.
 */
@Service
public class IngestionService {

    private static final Logger log = LoggerFactory.getLogger(IngestionService.class);

    @Value("${abuseipdb.api.key}")
    private String abuseIpDbApiKey;

    @Value("${alienvault.api.key}")
    private String alienVaultApiKey;

    private final RestTemplate restTemplate = new RestTemplate();

    // -------------------------------------------------------
    //  AbuseIPDB – IP blacklist
    //  https://docs.abuseipdb.com/#blacklist-endpoint
    // -------------------------------------------------------
    public String fetchAbuseIPDB() {
        String url = "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&limit=100";

        HttpHeaders headers = new HttpHeaders();
        headers.set("Key", abuseIpDbApiKey);
        headers.set("Accept", "application/json");

        HttpEntity<String> entity = new HttpEntity<>(headers);
        try {
            ResponseEntity<String> response =
                    restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
            log.info("AbuseIPDB fetch OK – status {}", response.getStatusCode());
            return response.getBody();
        } catch (Exception ex) {
            log.error("AbuseIPDB fetch failed: {}", ex.getMessage());
            return "{\"error\":\"AbuseIPDB unreachable\",\"data\":[]}";
        }
    }

    // -------------------------------------------------------
    //  AlienVault OTX – recent IPv4 pulses
    //  https://otx.alienvault.com/api/v1/pulses/subscribed
    // -------------------------------------------------------
    public String fetchAlienVault() {
        String url = "https://otx.alienvault.com/api/v1/indicators/IPv4/subscribed?limit=100";

        HttpHeaders headers = new HttpHeaders();
        headers.set("X-OTX-API-KEY", alienVaultApiKey);
        headers.set("Accept", "application/json");

        HttpEntity<String> entity = new HttpEntity<>(headers);
        try {
            ResponseEntity<String> response =
                    restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
            log.info("AlienVault fetch OK – status {}", response.getStatusCode());
            return response.getBody();
        } catch (Exception ex) {
            log.error("AlienVault fetch failed: {}", ex.getMessage());
            return "{\"error\":\"AlienVault unreachable\",\"results\":[]}";
        }
    }
}