package com.threat.extraction.consumer;

import com.threat.extraction.service.ExtractionService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("RawThreatConsumer Unit Tests")
class RawThreatConsumerTest {

    @Mock
    private ExtractionService extractionService;

    @InjectMocks
    private RawThreatConsumer rawThreatConsumer;

    @Test
    @DisplayName("consume() delegates message to ExtractionService.extractAndPublish()")
    void consume_delegatesToExtractionService() {
        String message = "{\"source\":\"ABUSEIPDB\",\"payload\":{\"data\":[]}}";

        rawThreatConsumer.consume(message);

        verify(extractionService, times(1)).extractAndPublish(message);
    }

    @Test
    @DisplayName("consume() passes exact message string without modification")
    void consume_passesExactMessage() {
        String message = "{\"source\":\"ALIENVAULT\",\"payload\":{\"results\":[]}}";

        rawThreatConsumer.consume(message);

        verify(extractionService).extractAndPublish(eq(message));
    }

    @Test
    @DisplayName("consume() handles empty string without throwing")
    void consume_emptyMessage_doesNotThrow() {
        rawThreatConsumer.consume("");
        verify(extractionService, times(1)).extractAndPublish("");
    }
}
