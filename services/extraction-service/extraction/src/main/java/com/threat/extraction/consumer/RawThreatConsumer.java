package com.threat.extraction.consumer;

import com.threat.extraction.service.ExtractionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

/**
 * RawThreatConsumer
 *
 * Kafka Consumer that subscribes to the "raw-threat-data" topic.
 * Each message is a tagged JSON payload (source + raw API response).
 * Delegates parsing and IOC extraction to ExtractionService.
 */
@Component
public class RawThreatConsumer {

    private static final Logger log = LoggerFactory.getLogger(RawThreatConsumer.class);

    private final ExtractionService extractionService;

    public RawThreatConsumer(ExtractionService extractionService) {
        this.extractionService = extractionService;
    }

    @KafkaListener(topics = "raw-threat-data", groupId = "extraction-group")
    public void consume(String message) {
        log.info("Received raw-threat-data message (length={})", message.length());
        extractionService.extractAndPublish(message);
    }
}