package com.threat.ranking.scheduler;

import com.threat.ranking.service.RankingService;
import com.threat.ranking.service.RankingService.RankResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("RankingScheduler Unit Tests")
class RankingSchedulerTest {

    @Mock
    private RankingService rankingService;

    @Mock
    private RestTemplate restTemplate;

    @InjectMocks
    private RankingScheduler rankingScheduler;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(rankingScheduler, "processingServiceUrl", "http://localhost:8083");
        ReflectionTestUtils.setField(rankingScheduler, "restTemplate", restTemplate);
    }

    @Test
    @DisplayName("rankPendingIocs() ranks each VALIDATED IOC returned by Processing Service")
    void rankPendingIocs_ranksAllValidatedIocs() throws Exception {
        String validatedIocsJson = """
                [
                  {"id":1,"value":"203.0.113.5","type":"IP"},
                  {"id":2,"value":"evil.com","type":"DOMAIN"}
                ]
                """;
        when(restTemplate.getForEntity(anyString(), eq(String.class)))
                .thenReturn(new ResponseEntity<>(validatedIocsJson, HttpStatus.OK));
        when(rankingService.rank(anyLong(), anyString(), anyString()))
                .thenReturn(new RankResult(50, "MEDIUM", 5, "US"));

        rankingScheduler.rankPendingIocs();

        verify(rankingService, times(1)).rank(1L, "203.0.113.5", "IP");
        verify(rankingService, times(1)).rank(2L, "evil.com", "DOMAIN");
    }

    @Test
    @DisplayName("rankPendingIocs() does nothing when no VALIDATED IOCs exist")
    void rankPendingIocs_emptyList_skipsRanking() throws Exception {
        when(restTemplate.getForEntity(anyString(), eq(String.class)))
                .thenReturn(new ResponseEntity<>("[]", HttpStatus.OK));

        rankingScheduler.rankPendingIocs();

        verify(rankingService, never()).rank(anyLong(), anyString(), anyString());
    }

    @Test
    @DisplayName("rankPendingIocs() handles Processing Service error gracefully")
    void rankPendingIocs_httpError_doesNotThrow() {
        when(restTemplate.getForEntity(anyString(), eq(String.class)))
                .thenReturn(new ResponseEntity<>(null, HttpStatus.SERVICE_UNAVAILABLE));

        // Should not throw
        rankingScheduler.rankPendingIocs();

        verify(rankingService, never()).rank(anyLong(), anyString(), anyString());
    }

    @Test
    @DisplayName("rankPendingIocs() handles connection exception gracefully")
    void rankPendingIocs_exception_doesNotThrow() {
        when(restTemplate.getForEntity(anyString(), eq(String.class)))
                .thenThrow(new RuntimeException("Connection refused"));

        // Should not propagate – scheduler must stay alive
        rankingScheduler.rankPendingIocs();

        verify(rankingService, never()).rank(anyLong(), anyString(), anyString());
    }

    @Test
    @DisplayName("rankPendingIocs() queries the VALIDATED status endpoint")
    void rankPendingIocs_queriesCorrectEndpoint() throws Exception {
        when(restTemplate.getForEntity(anyString(), eq(String.class)))
                .thenReturn(new ResponseEntity<>("[]", HttpStatus.OK));

        rankingScheduler.rankPendingIocs();

        verify(restTemplate).getForEntity(
                contains("/api/v1/processing/iocs/status/VALIDATED"),
                eq(String.class)
        );
    }
}
