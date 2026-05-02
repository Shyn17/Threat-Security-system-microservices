package com.threat.ranking.scheduler;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.threat.ranking.service.RankingService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

/**
 * RankingScheduler
 *
 * Periodically polls the Processing Service for VALIDATED (un-ranked) IOCs
 * and triggers the Ranking Service to score them.
 *
 * Runs every 60 seconds by default (configurable via ranking.scheduler.interval-ms).
 */
@Component
public class RankingScheduler {

    private static final Logger log = LoggerFactory.getLogger(RankingScheduler.class);

    @Value("${processing.service.url}")
    private String processingServiceUrl;

    private final RankingService rankingService;
    private final RestTemplate   restTemplate = new RestTemplate();
    private final ObjectMapper   mapper       = new ObjectMapper();

    public RankingScheduler(RankingService rankingService) {
        this.rankingService = rankingService;
    }

    @Scheduled(fixedDelayString = "${ranking.scheduler.interval-ms:60000}")
    public void rankPendingIocs() {
        try {
            String url = processingServiceUrl + "/api/v1/processing/iocs/status/VALIDATED";
            ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);

            if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) return;

            JsonNode iocs = mapper.readTree(response.getBody());
            if (!iocs.isArray() || iocs.isEmpty()) {
                log.debug("No VALIDATED IOCs to rank.");
                return;
            }

            log.info("Found {} VALIDATED IOCs to rank", iocs.size());
            for (JsonNode ioc : iocs) {
                long   id    = ioc.get("id").asLong();
                String value = ioc.get("value").asText();
                String type  = ioc.get("type").asText();
                rankingService.rank(id, value, type);
                // Small delay to avoid rate limiting on AbuseIPDB free tier
                Thread.sleep(500);
            }
        } catch (Exception e) {
            log.error("Ranking scheduler error: {}", e.getMessage());
        }
    }
}
