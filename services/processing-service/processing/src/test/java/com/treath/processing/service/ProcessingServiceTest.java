package com.treath.processing.service;

import com.treath.processing.model.IocRecord;
import com.treath.processing.repository.IocRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("ProcessingService Unit Tests")
class ProcessingServiceTest {

    @Mock
    private IocRepository iocRepository;

    @InjectMocks
    private ProcessingService processingService;

    // ── processIocEvent: happy path ───────────────────────────────────────────

    @Test
    @DisplayName("Valid public IP is persisted with VALIDATED status")
    void processIocEvent_validPublicIp_savesRecord() {
        String json = "{\"value\":\"203.0.113.5\",\"type\":\"IP\",\"source\":\"AbuseIPDB\"}";
        when(iocRepository.findByValueAndSource("203.0.113.5", "AbuseIPDB")).thenReturn(Optional.empty());

        IocRecord saved = IocRecord.builder()
                .id(1L).value("203.0.113.5").type("IP").source("AbuseIPDB").status("VALIDATED").build();
        when(iocRepository.save(any())).thenReturn(saved);

        IocRecord result = processingService.processIocEvent(json);

        assertThat(result).isNotNull();
        assertThat(result.getStatus()).isEqualTo("VALIDATED");

        ArgumentCaptor<IocRecord> captor = ArgumentCaptor.forClass(IocRecord.class);
        verify(iocRepository).save(captor.capture());
        assertThat(captor.getValue().getValue()).isEqualTo("203.0.113.5");
        assertThat(captor.getValue().getType()).isEqualTo("IP");
    }

    @Test
    @DisplayName("Valid domain is persisted with VALIDATED status")
    void processIocEvent_validDomain_savesRecord() {
        String json = "{\"value\":\"malicious.example.com\",\"type\":\"DOMAIN\",\"source\":\"AlienVault\"}";
        when(iocRepository.findByValueAndSource("malicious.example.com", "AlienVault")).thenReturn(Optional.empty());

        IocRecord saved = IocRecord.builder()
                .id(2L).value("malicious.example.com").type("DOMAIN").source("AlienVault").status("VALIDATED").build();
        when(iocRepository.save(any())).thenReturn(saved);

        IocRecord result = processingService.processIocEvent(json);

        assertThat(result).isNotNull();
        assertThat(result.getStatus()).isEqualTo("VALIDATED");
    }

    // ── processIocEvent: deduplication ───────────────────────────────────────

    @Test
    @DisplayName("Duplicate IOC is returned without re-saving")
    void processIocEvent_duplicate_returnsExistingWithoutSave() {
        String json = "{\"value\":\"203.0.113.5\",\"type\":\"IP\",\"source\":\"AbuseIPDB\"}";
        IocRecord existing = IocRecord.builder().id(10L).value("203.0.113.5").source("AbuseIPDB").build();
        when(iocRepository.findByValueAndSource("203.0.113.5", "AbuseIPDB")).thenReturn(Optional.of(existing));

        IocRecord result = processingService.processIocEvent(json);

        assertThat(result.getId()).isEqualTo(10L);
        verify(iocRepository, never()).save(any());
    }

    // ── processIocEvent: validation failures ─────────────────────────────────

    @ParameterizedTest(name = "Private IP ''{0}'' should be rejected")
    @ValueSource(strings = {"10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1"})
    @DisplayName("Private/loopback IPs are rejected by validation")
    void processIocEvent_privateIp_returnsNull(String privateIp) {
        String json = String.format("{\"value\":\"%s\",\"type\":\"IP\",\"source\":\"AbuseIPDB\"}", privateIp);

        IocRecord result = processingService.processIocEvent(json);

        assertThat(result).isNull();
        verify(iocRepository, never()).save(any());
    }

    @Test
    @DisplayName("Malformed IP address is rejected")
    void processIocEvent_malformedIp_returnsNull() {
        String json = "{\"value\":\"999.999.999.999\",\"type\":\"IP\",\"source\":\"AbuseIPDB\"}";

        IocRecord result = processingService.processIocEvent(json);

        assertThat(result).isNull();
    }

    @Test
    @DisplayName("Invalid domain (no TLD) is rejected")
    void processIocEvent_invalidDomain_returnsNull() {
        String json = "{\"value\":\"notadomain\",\"type\":\"DOMAIN\",\"source\":\"AlienVault\"}";

        IocRecord result = processingService.processIocEvent(json);

        assertThat(result).isNull();
    }

    @Test
    @DisplayName("Blank value results in null return")
    void processIocEvent_blankValue_returnsNull() {
        String json = "{\"value\":\"\",\"type\":\"IP\",\"source\":\"AbuseIPDB\"}";

        IocRecord result = processingService.processIocEvent(json);

        assertThat(result).isNull();
    }

    @Test
    @DisplayName("Malformed JSON is handled gracefully, returns null")
    void processIocEvent_malformedJson_returnsNull() {
        IocRecord result = processingService.processIocEvent("{not valid json}");

        assertThat(result).isNull();
        verify(iocRepository, never()).save(any());
    }

    // ── updateSeverity ────────────────────────────────────────────────────────

    @ParameterizedTest(name = "Score {0} should map to severity {1}")
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
    @DisplayName("updateSeverity maps scores to correct severity labels")
    void updateSeverity_correctSeverityMapping(int score, String expectedSeverity) {
        IocRecord record = IocRecord.builder()
                .id(1L).value("203.0.113.5").type("IP").source("AbuseIPDB").status("VALIDATED").build();
        when(iocRepository.findById(1L)).thenReturn(Optional.of(record));
        when(iocRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        IocRecord result = processingService.updateSeverity(1L, score, "US", 5);

        assertThat(result.getSeverity()).isEqualTo(expectedSeverity.trim());
        assertThat(result.getStatus()).isEqualTo("RANKED");
        assertThat(result.getSeverityScore()).isEqualTo(score);
    }

    @Test
    @DisplayName("updateSeverity throws RuntimeException for unknown IOC id")
    void updateSeverity_unknownId_throwsException() {
        when(iocRepository.findById(999L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> processingService.updateSeverity(999L, 80, "CN", 10))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("999");
    }

    @Test
    @DisplayName("updateSeverity stores country code and report count correctly")
    void updateSeverity_storesEnrichmentData() {
        IocRecord record = IocRecord.builder().id(5L).value("8.8.8.8").type("IP").source("AbuseIPDB").build();
        when(iocRepository.findById(5L)).thenReturn(Optional.of(record));
        when(iocRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        IocRecord result = processingService.updateSeverity(5L, 90, "US", 42);

        assertThat(result.getCountryCode()).isEqualTo("US");
        assertThat(result.getReportCount()).isEqualTo(42);
    }
}
