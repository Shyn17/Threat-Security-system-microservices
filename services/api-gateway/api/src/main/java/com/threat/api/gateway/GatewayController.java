package com.threat.api.gateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Enumeration;
import java.util.Map;

/**
 * GatewayController
 *
 * A lightweight reverse-proxy API Gateway that routes all incoming requests
 * to the appropriate downstream microservice based on the URL path prefix.
 *
 * Routing Table (all on port 8080):
 *   /api/v1/ingest/**      → ingestion-service  (8081)
 *   /api/v1/extract/**     → extraction-service (8082)
 *   /api/v1/processing/**  → processing-service (8083)
 *   /api/v1/rank/**        → ranking-service    (8084)
 *   /api/v1/db/**          → database-service   (8085)
 *   /api/v1/analytics/**   → analytics-service  (8086)
 *   /gateway/health        → gateway health check
 *   /gateway/routes        → list all registered routes
 */
@RestController
@CrossOrigin(origins = "*")
public class GatewayController {

    private static final Logger log = LoggerFactory.getLogger(GatewayController.class);

    @Value("${gateway.ingestion.url}")
    private String ingestionUrl;

    @Value("${gateway.extraction.url}")
    private String extractionUrl;

    @Value("${gateway.processing.url}")
    private String processingUrl;

    @Value("${gateway.ranking.url}")
    private String rankingUrl;

    @Value("${gateway.database.url}")
    private String databaseUrl;

    @Value("${gateway.analytics.url}")
    private String analyticsUrl;

    @Autowired
    private RestTemplate restTemplate;

    // ── Health & Info ─────────────────────────────────────────────────────────

    @GetMapping("/gateway/health")
    public ResponseEntity<Map<String, Object>> health() {
        return ResponseEntity.ok(Map.of(
                "service", "api-gateway",
                "status",  "UP",
                "port",    8080
        ));
    }

    @GetMapping("/gateway/routes")
    public ResponseEntity<Map<String, Object>> routes() {
        return ResponseEntity.ok(Map.of(
                "routes", Map.of(
                        "/api/v1/ingest/**",     ingestionUrl,
                        "/api/v1/extract/**",    extractionUrl,
                        "/api/v1/processing/**", processingUrl,
                        "/api/v1/rank/**",       rankingUrl,
                        "/api/v1/db/**",         databaseUrl,
                        "/api/v1/analytics/**",  analyticsUrl
                )
        ));
    }

    // ── Route: Ingestion Service ──────────────────────────────────────────────

    @RequestMapping("/api/v1/ingest/**")
    public ResponseEntity<String> proxyIngestion(HttpServletRequest request,
                                                  @RequestBody(required = false) String body) {
        return proxy(ingestionUrl, request, body);
    }

    // ── Route: Extraction Service ─────────────────────────────────────────────

    @RequestMapping("/api/v1/extract/**")
    public ResponseEntity<String> proxyExtraction(HttpServletRequest request,
                                                    @RequestBody(required = false) String body) {
        return proxy(extractionUrl, request, body);
    }

    // ── Route: Processing Service ─────────────────────────────────────────────

    @RequestMapping("/api/v1/processing/**")
    public ResponseEntity<String> proxyProcessing(HttpServletRequest request,
                                                    @RequestBody(required = false) String body) {
        return proxy(processingUrl, request, body);
    }

    // ── Route: Ranking Service ────────────────────────────────────────────────

    @RequestMapping("/api/v1/rank/**")
    public ResponseEntity<String> proxyRanking(HttpServletRequest request,
                                                @RequestBody(required = false) String body) {
        return proxy(rankingUrl, request, body);
    }

    // ── Route: Database Service ───────────────────────────────────────────────

    @RequestMapping("/api/v1/db/**")
    public ResponseEntity<String> proxyDatabase(HttpServletRequest request,
                                                 @RequestBody(required = false) String body) {
        return proxy(databaseUrl, request, body);
    }

    // ── Route: Analytics Service ──────────────────────────────────────────────

    @RequestMapping("/api/v1/analytics/**")
    public ResponseEntity<String> proxyAnalytics(HttpServletRequest request,
                                                   @RequestBody(required = false) String body) {
        return proxy(analyticsUrl, request, body);
    }

    // ── Core Proxy Logic ──────────────────────────────────────────────────────

    private ResponseEntity<String> proxy(String baseUrl,
                                          HttpServletRequest request,
                                          String body) {
        try {
            // Build the target URL: baseUrl + path + query string
            String path        = request.getRequestURI();
            String queryString = request.getQueryString();
            String targetUrl   = baseUrl + path + (queryString != null ? "?" + queryString : "");

            log.info("[GATEWAY] {} {} → {}", request.getMethod(), path, targetUrl);

            // Forward request headers (except Host)
            HttpHeaders headers = new HttpHeaders();
            Enumeration<String> headerNames = request.getHeaderNames();
            while (headerNames.hasMoreElements()) {
                String name = headerNames.nextElement();
                if (!name.equalsIgnoreCase("host")) {
                    headers.set(name, request.getHeader(name));
                }
            }
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpMethod method = HttpMethod.valueOf(request.getMethod());
            HttpEntity<String> entity = new HttpEntity<>(body, headers);

            ResponseEntity<String> response =
                    restTemplate.exchange(URI.create(targetUrl), method, entity, String.class);

            log.info("[GATEWAY] ← {} from {}", response.getStatusCode(), targetUrl);
            return response;

        } catch (HttpClientErrorException ex) {
            log.warn("[GATEWAY] Downstream error {}: {}", ex.getStatusCode(), ex.getMessage());
            return ResponseEntity.status(ex.getStatusCode()).body(ex.getResponseBodyAsString());
        } catch (Exception ex) {
            log.error("[GATEWAY] Routing error: {}", ex.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                    .body("{\"error\":\"Gateway routing failed\",\"message\":\"" + ex.getMessage() + "\"}");
        }
    }
}
