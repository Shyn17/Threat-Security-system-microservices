package com.threat.ranking.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

/**
 * RankingService
 *
 * Queries external ranking APIs to determine a severity score for each IOC.
 *
 * For IP addresses  → AbuseIPDB /check endpoint returns abuseConfidenceScore (0–100)
 * For domain names  → AlienVault OTX /indicators/domain/{domain}/general
 *                     (pulse_count + validation list) + lightweight structural heuristic
 *
 * After scoring, the service calls the Processing Service REST API to update
 * the severity score for the persisted IocRecord.
 */
@Service
public class RankingService {

    private static final Logger log = LoggerFactory.getLogger(RankingService.class);

    @Value("${abuseipdb.api.key}")
    private String abuseIpDbApiKey;

    @Value("${alienvault.api.key}")
    private String alienVaultApiKey;

    @Value("${processing.service.url}")
    private String processingServiceUrl;

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper  mapper       = new ObjectMapper();

    // -------------------------------------------------------
    //  Rank a single IOC – main entry point
    // -------------------------------------------------------
    public RankResult rank(Long iocId, String value, String type) {
        RankResult result = switch (type.toUpperCase()) {
            case "IP"     -> rankIp(value);
            case "DOMAIN" -> rankDomain(value);
            default       -> new RankResult(0, "UNKNOWN", 0, "");
        };

        // Notify Processing Service to update severity (skip for ad-hoc checks with id=-1)
        if (iocId != null && iocId > 0) {
            notifyProcessingService(iocId, result);
        }
        return result;
    }

    // -------------------------------------------------------
    //  IP ranking via AbuseIPDB /check
    // -------------------------------------------------------
    private RankResult rankIp(String ip) {
        String url = "https://api.abuseipdb.com/api/v2/check?ipAddress=" + ip
                     + "&maxAgeInDays=90&verbose";

        HttpHeaders headers = new HttpHeaders();
        headers.set("Key", abuseIpDbApiKey);
        headers.set("Accept", "application/json");
        HttpEntity<String> entity = new HttpEntity<>(headers);

        try {
            ResponseEntity<String> response =
                    restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
            JsonNode root = mapper.readTree(response.getBody());
            JsonNode data = root.get("data");

            int score       = data.has("abuseConfidenceScore") ? data.get("abuseConfidenceScore").asInt() : 0;
            int reportCount = data.has("totalReports")         ? data.get("totalReports").asInt()         : 0;
            String country  = data.has("countryCode")          ? data.get("countryCode").asText()         : "";
            String severity = deriveSeverity(score);

            log.info("IP ranked [{}] -> score={} severity={} country={}", ip, score, severity, country);
            return new RankResult(score, severity, reportCount, country);

        } catch (Exception e) {
            log.error("IP ranking failed [{}]: {}", ip, e.getMessage());
            return new RankResult(0, "UNKNOWN", 0, "");
        }
    }

    // -------------------------------------------------------
    //  Domain ranking via AlienVault OTX + structural heuristic
    //
    //  OTX endpoint: GET /api/v1/indicators/domain/{domain}/general
    //  Key fields used:
    //    - pulse_info.count   -> how many OTX threat pulses reference this domain
    //    - validation         -> list of validations (malicious flags)
    // -------------------------------------------------------
    private RankResult rankDomain(String domain) {
        int otxScore       = 0;
        int heuristicScore = 0;

        // 1. AlienVault OTX API call
        try {
            String url = "https://otx.alienvault.com/api/v1/indicators/domain/" + domain + "/general";

            HttpHeaders headers = new HttpHeaders();
            headers.set("X-OTX-API-KEY", alienVaultApiKey);
            headers.set("Accept", "application/json");
            HttpEntity<String> entity = new HttpEntity<>(headers);

            ResponseEntity<String> response =
                    restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
            JsonNode root = mapper.readTree(response.getBody());

            // pulse_info.count: number of threat intelligence pulses mentioning this domain
            int pulseCount = 0;
            if (root.has("pulse_info") && root.get("pulse_info").has("count")) {
                pulseCount = root.get("pulse_info").get("count").asInt();
            }

            // validation: list of objects with 'name' field (e.g. "malicious")
            int maliciousFlags = 0;
            if (root.has("validation") && root.get("validation").isArray()) {
                for (JsonNode v : root.get("validation")) {
                    if (v.has("name") && v.get("name").asText().toLowerCase().contains("malicious")) {
                        maliciousFlags++;
                    }
                }
            }

            // Score: pulses contribute up to 60 points, malicious flags up to 40
            otxScore = Math.min(pulseCount * 5, 60) + Math.min(maliciousFlags * 20, 40);
            log.info("OTX domain check [{}] -> pulses={} maliciousFlags={} otxScore={}",
                    domain, pulseCount, maliciousFlags, otxScore);

        } catch (Exception e) {
            log.warn("OTX domain lookup failed for [{}]: {} – falling back to heuristic only",
                    domain, e.getMessage());
        }

        // 2. Structural heuristic (supplements OTX score)
        // Suspicious TLDs commonly used in phishing
        String[] suspiciousTlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club"};
        for (String tld : suspiciousTlds) {
            if (domain.toLowerCase().endsWith(tld)) { heuristicScore += 25; break; }
        }
        // Very long domain (common in DGA malware)
        if (domain.length() > 50) heuristicScore += 15;
        // Excessive hyphens
        long hyphens = domain.chars().filter(c -> c == '-').count();
        if (hyphens >= 3) heuristicScore += 10;
        // High Shannon entropy (random-looking – DGA indicator)
        if (looksRandom(domain)) heuristicScore += 20;

        // 3. Combine scores
        int finalScore = Math.min(otxScore + heuristicScore, 100);
        String severity = deriveSeverity(finalScore);

        log.info("DOMAIN ranked [{}] -> otx={} heuristic={} final={} severity={}",
                domain, otxScore, heuristicScore, finalScore, severity);
        return new RankResult(finalScore, severity, 0, "");
    }

    // -------------------------------------------------------
    //  Notify Processing Service via REST PATCH
    // -------------------------------------------------------
    private void notifyProcessingService(Long iocId, RankResult result) {
        try {
            String url = processingServiceUrl
                    + "/api/v1/processing/iocs/" + iocId + "/severity"
                    + "?score="        + result.score()
                    + "&countryCode="  + result.countryCode()
                    + "&reportCount="  + result.reportCount();

            restTemplate.patchForObject(url, null, String.class);
            log.info("Processing service updated for IOC id={}", iocId);
        } catch (Exception e) {
            log.error("Failed to notify processing service for IOC id={}: {}", iocId, e.getMessage());
        }
    }

    // -------------------------------------------------------
    //  Helpers
    // -------------------------------------------------------
    private String deriveSeverity(int score) {
        if (score <= 25) return "LOW";
        if (score <= 50) return "MEDIUM";
        if (score <= 75) return "HIGH";
        return "CRITICAL";
    }

    /** Shannon entropy estimate for DGA detection */
    private boolean looksRandom(String domain) {
        String stripped = domain.replaceAll("\\.[^.]+$", ""); // remove TLD
        if (stripped.length() < 8) return false;
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : stripped.toCharArray()) freq.merge(c, 1, Integer::sum);
        double entropy = freq.values().stream()
                .mapToDouble(count -> {
                    double p = (double) count / stripped.length();
                    return -p * (Math.log(p) / Math.log(2));
                }).sum();
        return entropy > 3.8;
    }

    // Inner result record
    public record RankResult(int score, String severity, int reportCount, String countryCode) {}
}
