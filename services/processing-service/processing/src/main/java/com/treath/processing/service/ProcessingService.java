package com.treath.processing.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.treath.processing.model.IocRecord;
import com.treath.processing.repository.IocRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * ProcessingService
 *
 * Validates IOC events received from the "extracted-iocs" Kafka topic,
 * filters out duplicates, persists valid records to MySQL, and forwards
 * validated IOCs to the "validated-iocs" Kafka topic so the Ranking Service
 * can enrich them with severity scores.
 *
 * Validation rules:
 *   IP     – must match IPv4 format
 *   DOMAIN – must match domain / hostname format
 *   Both   – must not be blank or null
 */
@Service
public class ProcessingService {

    private static final Logger log = LoggerFactory.getLogger(ProcessingService.class);

    private final IocRepository iocRepository;
    private final ObjectMapper  mapper = new ObjectMapper();

    public ProcessingService(IocRepository iocRepository) {
        this.iocRepository = iocRepository;
    }

    // -------------------------------------------------------
    //  Main entry-point called by the Kafka listener
    // -------------------------------------------------------
    @Transactional
    public IocRecord processIocEvent(String json) {
        try {
            // Deserialize the IocEvent JSON sent by extraction-service
            var node  = mapper.readTree(json);
            String value  = node.has("value")  ? node.get("value").asText().trim()  : "";
            String type   = node.has("type")   ? node.get("type").asText().trim()   : "";
            String source = node.has("source") ? node.get("source").asText().trim() : "UNKNOWN";

            if (value.isBlank() || type.isBlank()) {
                log.warn("Skipping IOC with blank value/type: {}", json);
                return null;
            }

            // ── Validate format ──────────────────────────────
            if (!validate(value, type)) {
                log.warn("IOC failed validation [{}/{}]: {}", type, source, value);
                return null;
            }

            // ── Duplicate check ──────────────────────────────
            Optional<IocRecord> existing = iocRepository.findByValueAndSource(value, source);
            if (existing.isPresent()) {
                log.debug("Duplicate IOC skipped [{}/{}]: {}", type, source, value);
                return existing.get();
            }

            // ── Persist with VALIDATED status ────────────────
            IocRecord record = IocRecord.builder()
                    .value(value)
                    .type(type)
                    .source(source)
                    .status("VALIDATED")
                    .severityScore(0)
                    .severity("UNKNOWN")
                    .build();

            IocRecord saved = iocRepository.save(record);
            log.info("IOC persisted [id={}] [{}/{}]: {}", saved.getId(), type, source, value);
            return saved;

        } catch (Exception e) {
            log.error("Error processing IOC event: {}", e.getMessage());
            return null;
        }
    }

    // -------------------------------------------------------
    //  Update severity score (called by Ranking Service via REST)
    // -------------------------------------------------------
    @Transactional
    public IocRecord updateSeverity(Long id, int score, String countryCode, int reportCount) {
        return iocRepository.findById(id).map(record -> {
            record.setSeverityScore(score);
            record.setSeverity(deriveSeverity(score));
            record.setStatus("RANKED");
            record.setCountryCode(countryCode);
            record.setReportCount(reportCount);
            IocRecord updated = iocRepository.save(record);
            log.info("IOC ranked [id={}] score={} severity={}", id, score, updated.getSeverity());
            return updated;
        }).orElseThrow(() -> new RuntimeException("IOC not found: " + id));
    }

    // -------------------------------------------------------
    //  Validation helpers
    // -------------------------------------------------------
    private boolean validate(String value, String type) {
        return switch (type.toUpperCase()) {
            case "IP"     -> value.matches("^(\\d{1,3}\\.){3}\\d{1,3}$")
                             && isValidIpRange(value);
            case "DOMAIN" -> value.matches(
                    "^[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z]{2,})+$");
            default       -> false;
        };
    }

    private boolean isValidIpRange(String ip) {
        // Reject private/reserved ranges
        String[] parts = ip.split("\\.");
        int first = Integer.parseInt(parts[0]);
        int second = Integer.parseInt(parts[1]);
        if (first == 10) return false;             // 10.0.0.0/8
        if (first == 127) return false;            // loopback
        if (first == 172 && second >= 16 && second <= 31) return false;  // 172.16-31.x
        if (first == 192 && second == 168) return false;                 // 192.168.x
        return first >= 1 && first <= 254;
    }

    private String deriveSeverity(int score) {
        if (score <= 25) return "LOW";
        if (score <= 50) return "MEDIUM";
        if (score <= 75) return "HIGH";
        return "CRITICAL";
    }
}
