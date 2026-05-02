package com.treath.processing.consumer;

import com.treath.processing.service.ProcessingService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("ExtractedIocConsumer Unit Tests")
class ExtractedIocConsumerTest {

    @Mock
    private ProcessingService processingService;

    @InjectMocks
    private ExtractedIocConsumer extractedIocConsumer;

    @Test
    @DisplayName("consume() delegates message to ProcessingService.processIocEvent()")
    void consume_delegatesToProcessingService() {
        String message = "{\"value\":\"203.0.113.5\",\"type\":\"IP\",\"source\":\"AbuseIPDB\"}";

        extractedIocConsumer.consume(message);

        verify(processingService, times(1)).processIocEvent(message);
    }

    @Test
    @DisplayName("consume() passes exact message string without modification")
    void consume_passesExactMessage() {
        String message = "{\"value\":\"evil.com\",\"type\":\"DOMAIN\",\"source\":\"AlienVault\"}";

        extractedIocConsumer.consume(message);

        verify(processingService).processIocEvent(eq(message));
    }

    @Test
    @DisplayName("consume() handles empty string without throwing")
    void consume_emptyMessage_doesNotThrow() {
        extractedIocConsumer.consume("");
        verify(processingService, times(1)).processIocEvent("");
    }
}
