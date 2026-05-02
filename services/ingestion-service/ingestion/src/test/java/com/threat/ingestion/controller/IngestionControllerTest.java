package com.threat.ingestion.controller;

import com.threat.ingestion.service.IngestionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.test.web.servlet.MockMvc;

import java.util.concurrent.CompletableFuture;

import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(IngestionController.class)
@DisplayName("IngestionController Web Layer Tests")
class IngestionControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private IngestionService ingestionService;

    @MockBean
    private KafkaTemplate<String, String> kafkaTemplate;

    @BeforeEach
    void setUp() {
        // Stub kafkaTemplate.send() to return a completed future so .get() won't NPE
        when(kafkaTemplate.send(anyString(), anyString(), anyString()))
                .thenReturn(CompletableFuture.completedFuture(null));
    }

    // ── /health ───────────────────────────────────────────────────────────────

    @Test
    @DisplayName("GET /api/v1/ingest/health returns 200 with status UP")
    void health_returns200() throws Exception {
        mockMvc.perform(get("/api/v1/ingest/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.service").value("ingestion-service"));
    }

    // ── /abuseipdb ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("GET /api/v1/ingest/abuseipdb returns 200 and sends to Kafka")
    void ingestAbuseIPDB_returns200_andSendsToKafka() throws Exception {
        when(ingestionService.fetchAbuseIPDB()).thenReturn("{\"data\":[]}");

        mockMvc.perform(get("/api/v1/ingest/abuseipdb"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("sent"))
                .andExpect(jsonPath("$.source").value("AbuseIPDB"))
                .andExpect(jsonPath("$.topic").value("raw-threat-data"));

        verify(ingestionService, times(1)).fetchAbuseIPDB();
        verify(kafkaTemplate, times(1)).send(eq("raw-threat-data"), eq("abuseipdb"), anyString());
    }

    // ── /alienvault ───────────────────────────────────────────────────────────

    @Test
    @DisplayName("GET /api/v1/ingest/alienvault returns 200 and sends to Kafka")
    void ingestAlienVault_returns200_andSendsToKafka() throws Exception {
        when(ingestionService.fetchAlienVault()).thenReturn("{\"results\":[]}");

        mockMvc.perform(get("/api/v1/ingest/alienvault"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("sent"))
                .andExpect(jsonPath("$.source").value("AlienVault"));

        verify(ingestionService, times(1)).fetchAlienVault();
    }

    // ── /all ──────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("GET /api/v1/ingest/all calls both sources and returns 200")
    void ingestAll_callsBothSources() throws Exception {
        when(ingestionService.fetchAbuseIPDB()).thenReturn("{\"data\":[]}");
        when(ingestionService.fetchAlienVault()).thenReturn("{\"results\":[]}");

        mockMvc.perform(get("/api/v1/ingest/all"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("sent"))
                .andExpect(jsonPath("$.sources").value(containsString("AbuseIPDB")))
                .andExpect(jsonPath("$.sources").value(containsString("AlienVault")));

        verify(ingestionService, times(1)).fetchAbuseIPDB();
        verify(ingestionService, times(1)).fetchAlienVault();
    }

    @Test
    @DisplayName("GET /api/v1/ingest/abuseipdb tags payload with ABUSEIPDB source")
    void ingestAbuseIPDB_tagsPayloadWithSource() throws Exception {
        when(ingestionService.fetchAbuseIPDB()).thenReturn("{\"data\":[]}");

        mockMvc.perform(get("/api/v1/ingest/abuseipdb")).andExpect(status().isOk());

        verify(kafkaTemplate).send(
                eq("raw-threat-data"),
                eq("abuseipdb"),
                argThat((String msg) -> msg.contains("\"source\":\"ABUSEIPDB\""))
        );
    }
}
