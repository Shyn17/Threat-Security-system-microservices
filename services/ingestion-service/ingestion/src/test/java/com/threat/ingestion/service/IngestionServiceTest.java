package com.threat.ingestion.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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
@DisplayName("IngestionService Unit Tests")
class IngestionServiceTest {

    @InjectMocks
    private IngestionService ingestionService;

    @Mock
    private RestTemplate restTemplate;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(ingestionService, "abuseIpDbApiKey",  "test-abuse-key");
        ReflectionTestUtils.setField(ingestionService, "alienVaultApiKey", "test-av-key");
        // Inject the mock RestTemplate into the service
        ReflectionTestUtils.setField(ingestionService, "restTemplate", restTemplate);
    }

    // ── fetchAbuseIPDB ────────────────────────────────────────────────────────

    @Test
    @DisplayName("fetchAbuseIPDB: returns response body on HTTP 200")
    void fetchAbuseIPDB_success_returnsBody() {
        String mockBody = "{\"data\":[{\"ipAddress\":\"1.2.3.4\"}]}";
        ResponseEntity<String> mockResponse = new ResponseEntity<>(mockBody, HttpStatus.OK);

        when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
                .thenReturn(mockResponse);

        String result = ingestionService.fetchAbuseIPDB();

        assertThat(result).isEqualTo(mockBody);
        verify(restTemplate, times(1))
                .exchange(anyString(), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class));
    }

    @Test
    @DisplayName("fetchAbuseIPDB: returns fallback JSON on exception")
    void fetchAbuseIPDB_exception_returnsFallback() {
        when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
                .thenThrow(new RuntimeException("Connection refused"));

        String result = ingestionService.fetchAbuseIPDB();

        assertThat(result).contains("AbuseIPDB unreachable");
        assertThat(result).contains("\"data\":[]");
    }

    // ── fetchAlienVault ───────────────────────────────────────────────────────

    @Test
    @DisplayName("fetchAlienVault: returns response body on HTTP 200")
    void fetchAlienVault_success_returnsBody() {
        String mockBody = "{\"results\":[{\"indicator\":\"5.6.7.8\",\"type\":\"IPv4\"}]}";
        ResponseEntity<String> mockResponse = new ResponseEntity<>(mockBody, HttpStatus.OK);

        when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
                .thenReturn(mockResponse);

        String result = ingestionService.fetchAlienVault();

        assertThat(result).isEqualTo(mockBody);
    }

    @Test
    @DisplayName("fetchAlienVault: returns fallback JSON on exception")
    void fetchAlienVault_exception_returnsFallback() {
        when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
                .thenThrow(new RuntimeException("Timeout"));

        String result = ingestionService.fetchAlienVault();

        assertThat(result).contains("AlienVault unreachable");
        assertThat(result).contains("\"results\":[]");
    }

    @Test
    @DisplayName("fetchAbuseIPDB: sets correct Accept and Key headers")
    void fetchAbuseIPDB_setsCorrectHeaders() {
        ResponseEntity<String> mockResponse = new ResponseEntity<>("{\"data\":[]}", HttpStatus.OK);
        when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
                .thenReturn(mockResponse);

        ingestionService.fetchAbuseIPDB();

        verify(restTemplate).exchange(
                contains("abuseipdb.com"),
                eq(HttpMethod.GET),
                argThat(entity -> {
                    HttpHeaders h = ((HttpEntity<?>) entity).getHeaders();
                    return "test-abuse-key".equals(h.getFirst("Key")) &&
                           "application/json".equals(h.getFirst("Accept"));
                }),
                eq(String.class)
        );
    }
}
