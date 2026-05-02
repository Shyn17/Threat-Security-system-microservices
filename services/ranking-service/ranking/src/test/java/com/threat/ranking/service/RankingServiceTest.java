package com.threat.ranking.service;

import com.threat.ranking.service.RankingService.RankResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.*;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("RankingService Unit Tests")
class RankingServiceTest {

    @InjectMocks
    private RankingService rankingService;

    @Mock
    private RestTemplate restTemplate;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(rankingService, "abuseIpDbApiKey",    "test-abuse-key");
        ReflectionTestUtils.setField(rankingService, "alienVaultApiKey",   "test-av-key");
        ReflectionTestUtils.setField(rankingService, "processingServiceUrl", "http://localhost:8083");
        ReflectionTestUtils.setField(rankingService, "restTemplate", restTemplate);
    }

    // ── IP ranking ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("rank() IP: calls AbuseIPDB /check and returns RankResult")
    void rankIp_success_returnsRankResult() {
        String abuseIpDbResponse = """
                {"data":{"abuseConfidenceScore":90,"totalReports":50,"countryCode":"CN"}}
                """;
        when(restTemplate.exchange(contains("abuseipdb.com/api/v2/check"),
                eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
                .thenReturn(new ResponseEntity<>(abuseIpDbResponse, HttpStatus.OK));

        when(restTemplate.patchForObject(anyString(), any(), eq(String.class))).thenReturn("OK");

        RankResult result = rankingService.rank(1L, "203.0.113.5", "IP");

        assertThat(result.score()).isEqualTo(90);
        assertThat(result.severity()).isEqualTo("CRITICAL");
        assertThat(result.countryCode()).isEqualTo("CN");
        assertThat(result.reportCount()).isEqualTo(50);
    }

    @ParameterizedTest(name = "AbuseIPDB score {0} → severity {1}")
    @CsvSource({
        "0,   LOW",
        "25,  LOW",
        "26,  MEDIUM",
        "50,  MEDIUM",
        "51,  HIGH",
        "75,  HIGH",
        "76,  CRITICAL",
        "100, CRITICAL"
    })
    @DisplayName("IP rank: severity labels are derived correctly from score")
    void rankIp_correctSeverityDerivation(int score, String expectedSeverity) {
        String body = String.format(
                "{\"data\":{\"abuseConfidenceScore\":%d,\"totalReports\":1,\"countryCode\":\"US\"}}", score);
        when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(), eq(String.class)))
                .thenReturn(new ResponseEntity<>(body, HttpStatus.OK));
        when(restTemplate.patchForObject(anyString(), any(), eq(String.class))).thenReturn("OK");

        RankResult result = rankingService.rank(1L, "8.8.8.8", "IP");

        assertThat(result.severity()).isEqualTo(expectedSeverity.trim());
        assertThat(result.score()).isEqualTo(score);
    }

    @Test
    @DisplayName("rank() IP: AbuseIPDB failure returns UNKNOWN result")
    void rankIp_apiFailure_returnsUnknown() {
        when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(), eq(String.class)))
                .thenThrow(new RuntimeException("Connection refused"));

        RankResult result = rankingService.rank(1L, "1.2.3.4", "IP");

        assertThat(result.score()).isEqualTo(0);
        assertThat(result.severity()).isEqualTo("UNKNOWN");
    }

    // ── Domain ranking ────────────────────────────────────────────────────────

    @Test
    @DisplayName("rank() DOMAIN: OTX API called and contributes to score")
    void rankDomain_otxApiCalled_contributesToScore() {
        String otxResponse = """
                {"pulse_info":{"count":10},"validation":[{"name":"malicious"}]}
                """;
        when(restTemplate.exchange(contains("otx.alienvault.com"), eq(HttpMethod.GET),
                any(HttpEntity.class), eq(String.class)))
                .thenReturn(new ResponseEntity<>(otxResponse, HttpStatus.OK));
        when(restTemplate.patchForObject(anyString(), any(), eq(String.class))).thenReturn("OK");

        RankResult result = rankingService.rank(2L, "evil.com", "DOMAIN");

        // 10 pulses * 5 = 50, 1 malicious flag * 20 = 20 → 70 OTX + 0 heuristic = 70
        assertThat(result.score()).isGreaterThan(0);
        assertThat(result.severity()).isIn("MEDIUM", "HIGH", "CRITICAL");
    }

    @Test
    @DisplayName("rank() DOMAIN: OTX failure falls back to heuristic scoring")
    void rankDomain_otxFailure_fallsBackToHeuristic() {
        when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(), eq(String.class)))
                .thenThrow(new RuntimeException("OTX unreachable"));

        // ".xyz" TLD should trigger heuristic score of 25
        RankResult result = rankingService.rank(3L, "randomsite.xyz", "DOMAIN");

        assertThat(result.score()).isGreaterThanOrEqualTo(25);
        assertThat(result.severity()).isNotEqualTo("UNKNOWN");
    }

    @Test
    @DisplayName("rank() DOMAIN: clean domain scores LOW with no pulses")
    void rankDomain_cleanDomain_scoresLow() {
        String otxResponse = "{\"pulse_info\":{\"count\":0},\"validation\":[]}";
        when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(), eq(String.class)))
                .thenReturn(new ResponseEntity<>(otxResponse, HttpStatus.OK));
        when(restTemplate.patchForObject(anyString(), any(), eq(String.class))).thenReturn("OK");

        RankResult result = rankingService.rank(4L, "google.com", "DOMAIN");

        assertThat(result.score()).isLessThanOrEqualTo(25);
        assertThat(result.severity()).isEqualTo("LOW");
    }

    // ── Processing service notification ──────────────────────────────────────

    @Test
    @DisplayName("rank() notifies Processing Service via PATCH for valid iocId > 0")
    void rank_validIocId_notifiesProcessingService() {
        String body = "{\"data\":{\"abuseConfidenceScore\":80,\"totalReports\":10,\"countryCode\":\"US\"}}";
        when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(), eq(String.class)))
                .thenReturn(new ResponseEntity<>(body, HttpStatus.OK));
        when(restTemplate.patchForObject(anyString(), any(), eq(String.class))).thenReturn("OK");

        rankingService.rank(5L, "5.5.5.5", "IP");

        verify(restTemplate).patchForObject(contains("/api/v1/processing/iocs/5/severity"), any(), eq(String.class));
    }

    @Test
    @DisplayName("rank() skips Processing Service notification for iocId = -1 (ad-hoc check)")
    void rank_adHocCheck_skipsNotification() {
        String body = "{\"data\":{\"abuseConfidenceScore\":50,\"totalReports\":5,\"countryCode\":\"DE\"}}";
        when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(), eq(String.class)))
                .thenReturn(new ResponseEntity<>(body, HttpStatus.OK));

        rankingService.rank(-1L, "1.1.1.1", "IP");

        verify(restTemplate, never()).patchForObject(anyString(), any(), eq(String.class));
    }

    @Test
    @DisplayName("rank() unknown type returns UNKNOWN result without API calls")
    void rank_unknownType_returnsUnknown() {
        RankResult result = rankingService.rank(1L, "somevalue", "HASH");

        assertThat(result.score()).isEqualTo(0);
        assertThat(result.severity()).isEqualTo("UNKNOWN");
        verify(restTemplate, never()).exchange(anyString(), any(), any(), eq(String.class));
    }
}
