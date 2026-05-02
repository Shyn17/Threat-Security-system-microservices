package com.treath.processing.consumer;

import com.treath.processing.service.ProcessingService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

/**
 * ExtractedIocConsumer
 *
 * Subscribes to the "extracted-iocs" Kafka topic.
 * Each message is an IocEvent JSON produced by the Extraction Service.
 * Delegates validation and persistence to ProcessingService.
 */
@Component
public class ExtractedIocConsumer {

    private static final Logger log = LoggerFactory.getLogger(ExtractedIocConsumer.class);

    private final ProcessingService processingService;

    public ExtractedIocConsumer(ProcessingService processingService) {
        this.processingService = processingService;
    }

    @KafkaListener(topics = "extracted-iocs", groupId = "processing-group")
    public void consume(String message) {
        log.debug("Consumed extracted-iocs: {}", message);
        processingService.processIocEvent(message);
    }
}
