package com.threat.extraction.producer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.threat.extraction.model.IocEvent;   // ✅ THIS IMPORT IS REQUIRED
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

@Component
public class ExtractedIocProducer {

    private static final String TOPIC = "extracted-iocs";

    private final KafkaTemplate<String, String> kafkaTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public ExtractedIocProducer(KafkaTemplate<String, String> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    public void send(IocEvent iocEvent) {
        try {
            String payload = objectMapper.writeValueAsString(iocEvent);
            kafkaTemplate.send(TOPIC, payload);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}