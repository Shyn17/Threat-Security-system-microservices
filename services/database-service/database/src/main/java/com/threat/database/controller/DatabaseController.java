package com.threat.database.controller;

import com.threat.database.model.IocRecord;
import com.threat.database.repository.IocRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * DatabaseController
 *
 * Dedicated query and analytics REST API (read-only interface to the shared MySQL DB).
 *
 * GET /api/v1/db/iocs                     – all IOCs sorted by severity
 * GET /api/v1/db/iocs/{id}                – single IOC
 * GET /api/v1/db/iocs/type/{type}         – filter by IP|DOMAIN
 * GET /api/v1/db/iocs/severity/{severity} – filter by LOW|MEDIUM|HIGH|CRITICAL
 * GET /api/v1/db/iocs/source/{source}     – filter by source
 * GET /api/v1/db/iocs/country/{code}      – filter by country code
 * GET /api/v1/db/iocs/top?minScore=75     – top threats (score ≥ threshold)
 * GET /api/v1/db/iocs/ranked              – all fully-ranked IOCs
 * GET /api/v1/db/iocs/recent?hours=24     – IOCs ingested in last N hours
 * GET /api/v1/db/stats                    – summary statistics
 * GET /api/v1/db/health                   – liveness probe
 */
@RestController
@RequestMapping("/api/v1/db")
@CrossOrigin(origins = "*")
public class DatabaseController {

    private final IocRepository iocRepository;

    public DatabaseController(IocRepository iocRepository) {
        this.iocRepository = iocRepository;
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of("service", "database-service", "status", "UP"));
    }

    @PostMapping("/iocs")
    public ResponseEntity<IocRecord> createIoc(@RequestBody IocRecord iocRecord) {
        if (iocRecord.getCreatedAt() == null) {
            iocRecord.setCreatedAt(LocalDateTime.now());
        }
        if (iocRecord.getStatus() == null) {
            iocRecord.setStatus("PENDING");
        }
        if (iocRecord.getSeverity() == null) {
            iocRecord.setSeverity("UNKNOWN");
        }
        return ResponseEntity.ok(iocRepository.save(iocRecord));
    }

    @GetMapping("/iocs")
    public ResponseEntity<List<IocRecord>> getAllIocs() {
        return ResponseEntity.ok(iocRepository.findAllOrderedBySeverityDesc());
    }

    @GetMapping("/iocs/{id}")
    public ResponseEntity<IocRecord> getIoc(@PathVariable Long id) {
        return iocRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/iocs/type/{type}")
    public ResponseEntity<List<IocRecord>> getByType(@PathVariable String type) {
        return ResponseEntity.ok(iocRepository.findByType(type.toUpperCase()));
    }

    @GetMapping("/iocs/severity/{severity}")
    public ResponseEntity<List<IocRecord>> getBySeverity(@PathVariable String severity) {
        return ResponseEntity.ok(iocRepository.findBySeverity(severity.toUpperCase()));
    }

    @GetMapping("/iocs/source/{source}")
    public ResponseEntity<List<IocRecord>> getBySource(@PathVariable String source) {
        return ResponseEntity.ok(iocRepository.findBySource(source.toUpperCase()));
    }

    @GetMapping("/iocs/country/{code}")
    public ResponseEntity<List<IocRecord>> getByCountry(@PathVariable String code) {
        return ResponseEntity.ok(iocRepository.findByCountryCode(code.toUpperCase()));
    }

    @GetMapping("/iocs/top")
    public ResponseEntity<List<IocRecord>> getTopThreats(
            @RequestParam(defaultValue = "75") int minScore) {
        return ResponseEntity.ok(iocRepository.findBySeverityScoreGreaterThanEqual(minScore));
    }

    @GetMapping("/iocs/ranked")
    public ResponseEntity<List<IocRecord>> getRanked() {
        return ResponseEntity.ok(iocRepository.findRankedOrderedBySeverityDesc());
    }

    @GetMapping("/iocs/recent")
    public ResponseEntity<List<IocRecord>> getRecent(
            @RequestParam(defaultValue = "24") int hours) {
        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        return ResponseEntity.ok(iocRepository.findSince(since));
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        Map<String, Object> stats = new java.util.LinkedHashMap<>();
        stats.put("total",            iocRepository.count());
        stats.put("ips",              iocRepository.countByType("IP"));
        stats.put("domains",          iocRepository.countByType("DOMAIN"));
        stats.put("ranked",           iocRepository.countByStatus("RANKED"));
        stats.put("validated",        iocRepository.countByStatus("VALIDATED"));
        stats.put("pending",          iocRepository.countByStatus("PENDING"));
        stats.put("critical",         iocRepository.countBySeverity("CRITICAL"));
        stats.put("high",             iocRepository.countBySeverity("HIGH"));
        stats.put("medium",           iocRepository.countBySeverity("MEDIUM"));
        stats.put("low",              iocRepository.countBySeverity("LOW"));
        stats.put("sourceAbuseIPDB",  iocRepository.countBySource("AbuseIPDB"));
        stats.put("sourceAlienVault", iocRepository.countBySource("AlienVault"));
        return ResponseEntity.ok(stats);
    }
}
