package com.treath.processing.controller;

import com.treath.processing.model.IocRecord;
import com.treath.processing.repository.IocRepository;
import com.treath.processing.service.ProcessingService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * ProcessingController
 *
 * REST API for the Processing Service.
 * Allows the Ranking Service to POST severity updates, and provides
 * basic query endpoints for the Database / Analytics services.
 *
 * Base path: /api/v1/processing
 */
@RestController
@RequestMapping("/api/v1/processing")
@CrossOrigin(origins = "*")
public class ProcessingController {

    private final ProcessingService processingService;
    private final IocRepository iocRepository;

    public ProcessingController(ProcessingService processingService,
                                IocRepository iocRepository) {
        this.processingService = processingService;
        this.iocRepository     = iocRepository;
    }

    // ── Health ───────────────────────────────────────────────────────────
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of("service", "processing-service", "status", "UP"));
    }

    // ── List all IOCs ────────────────────────────────────────────────────
    @GetMapping("/iocs")
    public ResponseEntity<List<IocRecord>> getAllIocs() {
        return ResponseEntity.ok(iocRepository.findAllOrderedBySeverityDesc());
    }

    // ── Get single IOC ───────────────────────────────────────────────────
    @GetMapping("/iocs/{id}")
    public ResponseEntity<IocRecord> getIoc(@PathVariable Long id) {
        return iocRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // ── Filter by status ─────────────────────────────────────────────────
    @GetMapping("/iocs/status/{status}")
    public ResponseEntity<List<IocRecord>> getByStatus(@PathVariable String status) {
        return ResponseEntity.ok(iocRepository.findByStatus(status.toUpperCase()));
    }

    // ── Filter by type ───────────────────────────────────────────────────
    @GetMapping("/iocs/type/{type}")
    public ResponseEntity<List<IocRecord>> getByType(@PathVariable String type) {
        return ResponseEntity.ok(iocRepository.findByType(type.toUpperCase()));
    }

    // ── Filter by severity ───────────────────────────────────────────────
    @GetMapping("/iocs/severity/{severity}")
    public ResponseEntity<List<IocRecord>> getBySeverity(@PathVariable String severity) {
        return ResponseEntity.ok(iocRepository.findBySeverity(severity.toUpperCase()));
    }

    // ── Filter by source ─────────────────────────────────────────────────
    @GetMapping("/iocs/source/{source}")
    public ResponseEntity<List<IocRecord>> getBySource(@PathVariable String source) {
        return ResponseEntity.ok(iocRepository.findBySource(source.toUpperCase()));
    }

    // ── Top threats (score >= threshold) ─────────────────────────────────
    @GetMapping("/iocs/top")
    public ResponseEntity<List<IocRecord>> getTopThreats(
            @RequestParam(defaultValue = "75") int minScore) {
        return ResponseEntity.ok(iocRepository.findBySeverityScoreGreaterThanEqual(minScore));
    }

    // ── Update severity score (called by Ranking Service) ─────────────────
    @PatchMapping("/iocs/{id}/severity")
    public ResponseEntity<IocRecord> updateSeverity(
            @PathVariable Long id,
            @RequestParam int score,
            @RequestParam(required = false, defaultValue = "") String countryCode,
            @RequestParam(required = false, defaultValue = "0") int reportCount) {
        return ResponseEntity.ok(
                processingService.updateSeverity(id, score, countryCode, reportCount));
    }

    // ── Summary stats ─────────────────────────────────────────────────────
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        return ResponseEntity.ok(Map.of(
                "total",    iocRepository.count(),
                "ips",      iocRepository.countByType("IP"),
                "domains",  iocRepository.countByType("DOMAIN"),
                "pending",  iocRepository.countByStatus("PENDING"),
                "validated",iocRepository.countByStatus("VALIDATED"),
                "ranked",   iocRepository.countByStatus("RANKED"),
                "critical", iocRepository.countBySeverity("CRITICAL"),
                "high",     iocRepository.countBySeverity("HIGH"),
                "medium",   iocRepository.countBySeverity("MEDIUM"),
                "low",      iocRepository.countBySeverity("LOW")
        ));
    }
}
