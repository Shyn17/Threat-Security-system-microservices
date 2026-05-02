package com.threat.analytics.controller;

import com.threat.analytics.model.IocRecord;
import com.threat.analytics.repository.AnalyticsRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * AnalyticsController
 *
 * Provides aggregated threat-intelligence analytics and reporting.
 *
 *  GET /api/v1/analytics/summary          – full dashboard summary
 *  GET /api/v1/analytics/by-severity      – distribution by severity
 *  GET /api/v1/analytics/by-type          – IOC type breakdown (IP vs DOMAIN)
 *  GET /api/v1/analytics/by-source        – source breakdown
 *  GET /api/v1/analytics/by-country       – top countries
 *  GET /api/v1/analytics/top-threats      – highest-scoring IOCs
 *  GET /api/v1/analytics/trend?hours=24   – IOCs ingested in last N hours
 *  GET /api/v1/analytics/health           – liveness probe
 */
@RestController
@RequestMapping("/api/v1/analytics")
@CrossOrigin(origins = "*")
public class AnalyticsController {

    private final AnalyticsRepository analyticsRepository;

    public AnalyticsController(AnalyticsRepository analyticsRepository) {
        this.analyticsRepository = analyticsRepository;
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of("service", "analytics-service", "status", "UP"));
    }

    // ── Full dashboard summary ────────────────────────────────────────────
    @GetMapping("/summary")
    public ResponseEntity<Map<String, Object>> summary() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("totalIocs",        analyticsRepository.count());
        result.put("totalIps",         analyticsRepository.countByType("IP"));
        result.put("totalDomains",     analyticsRepository.countByType("DOMAIN"));
        result.put("ranked",           analyticsRepository.countByStatus("RANKED"));
        result.put("pending",          analyticsRepository.countByStatus("PENDING"));
        result.put("validated",        analyticsRepository.countByStatus("VALIDATED"));
        result.put("critical",         analyticsRepository.countBySeverity("CRITICAL"));
        result.put("high",             analyticsRepository.countBySeverity("HIGH"));
        result.put("medium",           analyticsRepository.countBySeverity("MEDIUM"));
        result.put("low",              analyticsRepository.countBySeverity("LOW"));
        result.put("avgSeverityScore", analyticsRepository.avgSeverityScore());
        result.put("maxSeverityScore", analyticsRepository.maxSeverityScore());
        result.put("abuseipdbCount",   analyticsRepository.countBySource("AbuseIPDB"));
        result.put("alienvaultCount",  analyticsRepository.countBySource("AlienVault"));
        return ResponseEntity.ok(result);
    }

    // ── Severity distribution ─────────────────────────────────────────────
    @GetMapping("/by-severity")
    public ResponseEntity<Map<String, Long>> bySeverity() {
        return ResponseEntity.ok(
                toMap(analyticsRepository.countBySeverityGrouped()));
    }

    // ── IOC type breakdown ────────────────────────────────────────────────
    @GetMapping("/by-type")
    public ResponseEntity<Map<String, Long>> byType() {
        return ResponseEntity.ok(toMap(analyticsRepository.countByTypeGrouped()));
    }

    // ── Source breakdown ──────────────────────────────────────────────────
    @GetMapping("/by-source")
    public ResponseEntity<Map<String, Long>> bySource() {
        return ResponseEntity.ok(toMap(analyticsRepository.countBySourceGrouped()));
    }

    // ── Top countries ─────────────────────────────────────────────────────
    @GetMapping("/by-country")
    public ResponseEntity<Map<String, Long>> byCountry(
            @RequestParam(defaultValue = "10") int limit) {
        Map<String, Long> result = new LinkedHashMap<>();
        analyticsRepository.countByCountryCodeGrouped().stream()
                .limit(limit)
                .forEach(row -> result.put((String) row[0], (Long) row[1]));
        return ResponseEntity.ok(result);
    }

    // ── Top threats ───────────────────────────────────────────────────────
    @GetMapping("/top-threats")
    public ResponseEntity<List<Map<String, Object>>> topThreats(
            @RequestParam(defaultValue = "20") int limit) {
        return ResponseEntity.ok(
                analyticsRepository.findCriticalAndHighThreats()
                        .stream().limit(limit)
                        .map(this::toSummaryMap)
                        .collect(Collectors.toList()));
    }

    // ── Trend: IOCs ingested in last N hours ──────────────────────────────
    @GetMapping("/trend")
    public ResponseEntity<Map<String, Object>> trend(
            @RequestParam(defaultValue = "24") int hours) {
        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        List<IocRecord> recent = analyticsRepository.findSince(since);
        return ResponseEntity.ok(Map.of(
                "hours",   hours,
                "count",   recent.size(),
                "records", recent.stream().map(this::toSummaryMap).collect(Collectors.toList())
        ));
    }

    // ── Helpers ───────────────────────────────────────────────────────────
    private Map<String, Long> toMap(List<Object[]> rows) {
        Map<String, Long> map = new LinkedHashMap<>();
        rows.forEach(row -> map.put(String.valueOf(row[0]), (Long) row[1]));
        return map;
    }

    private Map<String, Object> toSummaryMap(IocRecord r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id",            r.getId());
        m.put("value",         r.getValue());
        m.put("type",          r.getType());
        m.put("source",        r.getSource());
        m.put("severity",      r.getSeverity());
        m.put("severityScore", r.getSeverityScore());
        m.put("countryCode",   r.getCountryCode());
        m.put("reportCount",   r.getReportCount());
        m.put("createdAt",     r.getCreatedAt());
        return m;
    }
}
