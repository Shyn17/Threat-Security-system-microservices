package com.threat.ranking.controller;

import com.threat.ranking.service.RankingService;
import com.threat.ranking.service.RankingService.RankResult;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * RankingController
 *
 * REST API for the Ranking Service.
 *
 *  POST /api/v1/rank          – rank a single IOC (id, value, type)
 *  POST /api/v1/rank/ip       – quick rank an IP without DB update
 *  GET  /api/v1/rank/health   – liveness probe
 */
@RestController
@RequestMapping("/api/v1/rank")
@CrossOrigin(origins = "*")
public class RankingController {

    private final RankingService rankingService;

    public RankingController(RankingService rankingService) {
        this.rankingService = rankingService;
    }

    // ── Rank an IOC stored in the Processing Service ──────────────────────
    @PostMapping
    public ResponseEntity<Map<String, Object>> rank(
            @RequestParam Long   iocId,
            @RequestParam String value,
            @RequestParam String type) {

        RankResult result = rankingService.rank(iocId, value, type);
        return ResponseEntity.ok(Map.of(
                "iocId",       iocId,
                "value",       value,
                "type",        type,
                "score",       result.score(),
                "severity",    result.severity(),
                "reportCount", result.reportCount(),
                "countryCode", result.countryCode()
        ));
    }

    // ── Quick IP check (no DB update) ─────────────────────────────────────
    @GetMapping("/check/ip")
    public ResponseEntity<Map<String, Object>> checkIp(@RequestParam String ip) {
        RankResult result = rankingService.rank(-1L, ip, "IP");
        return ResponseEntity.ok(Map.of(
                "ip",          ip,
                "score",       result.score(),
                "severity",    result.severity(),
                "reportCount", result.reportCount(),
                "countryCode", result.countryCode()
        ));
    }

    // ── Quick domain check ───────────────────────────────────────────────
    @GetMapping("/check/domain")
    public ResponseEntity<Map<String, Object>> checkDomain(@RequestParam String domain) {
        RankResult result = rankingService.rank(-1L, domain, "DOMAIN");
        return ResponseEntity.ok(Map.of(
                "domain",   domain,
                "score",    result.score(),
                "severity", result.severity()
        ));
    }

    // ── Health ───────────────────────────────────────────────────────────
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of("service", "ranking-service", "status", "UP"));
    }
}
