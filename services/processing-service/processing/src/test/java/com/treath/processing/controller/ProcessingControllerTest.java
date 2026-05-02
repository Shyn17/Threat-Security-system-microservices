package com.treath.processing.controller;

import com.treath.processing.model.IocRecord;
import com.treath.processing.repository.IocRepository;
import com.treath.processing.service.ProcessingService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Optional;

import static org.hamcrest.Matchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(ProcessingController.class)
@DisplayName("ProcessingController Web Layer Tests")
class ProcessingControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private ProcessingService processingService;

    @MockBean
    private IocRepository iocRepository;

    private IocRecord sampleRecord() {
        return IocRecord.builder()
                .id(1L).value("203.0.113.5").type("IP").source("AbuseIPDB")
                .status("VALIDATED").severityScore(0).severity("UNKNOWN").build();
    }

    @Test
    @DisplayName("GET /api/v1/processing/health returns 200")
    void health_returns200() throws Exception {
        mockMvc.perform(get("/api/v1/processing/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }

    @Test
    @DisplayName("GET /api/v1/processing/iocs returns list of IOCs")
    void getAllIocs_returnsList() throws Exception {
        when(iocRepository.findAllOrderedBySeverityDesc()).thenReturn(List.of(sampleRecord()));

        mockMvc.perform(get("/api/v1/processing/iocs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].value").value("203.0.113.5"));
    }

    @Test
    @DisplayName("GET /api/v1/processing/iocs/{id} returns IOC when found")
    void getIoc_found_returns200() throws Exception {
        when(iocRepository.findById(1L)).thenReturn(Optional.of(sampleRecord()));

        mockMvc.perform(get("/api/v1/processing/iocs/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.value").value("203.0.113.5"))
                .andExpect(jsonPath("$.type").value("IP"));
    }

    @Test
    @DisplayName("GET /api/v1/processing/iocs/{id} returns 404 when not found")
    void getIoc_notFound_returns404() throws Exception {
        when(iocRepository.findById(99L)).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/v1/processing/iocs/99"))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("GET /api/v1/processing/iocs/status/VALIDATED filters by status")
    void getByStatus_returnsFilteredList() throws Exception {
        when(iocRepository.findByStatus("VALIDATED")).thenReturn(List.of(sampleRecord()));

        mockMvc.perform(get("/api/v1/processing/iocs/status/VALIDATED"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].status").value("VALIDATED"));
    }

    @Test
    @DisplayName("GET /api/v1/processing/iocs/type/IP filters by type")
    void getByType_returnsFilteredList() throws Exception {
        when(iocRepository.findByType("IP")).thenReturn(List.of(sampleRecord()));

        mockMvc.perform(get("/api/v1/processing/iocs/type/IP"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].type").value("IP"));
    }

    @Test
    @DisplayName("GET /api/v1/processing/iocs/top?minScore=75 returns high-score IOCs")
    void getTopThreats_returnsFilteredList() throws Exception {
        IocRecord criticalRecord = IocRecord.builder()
                .id(2L).value("8.8.8.8").type("IP").source("AbuseIPDB")
                .status("RANKED").severityScore(90).severity("CRITICAL").build();
        when(iocRepository.findBySeverityScoreGreaterThanEqual(75)).thenReturn(List.of(criticalRecord));

        mockMvc.perform(get("/api/v1/processing/iocs/top?minScore=75"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].severityScore").value(90));
    }

    @Test
    @DisplayName("PATCH /api/v1/processing/iocs/{id}/severity calls updateSeverity and returns updated record")
    void updateSeverity_returns200WithUpdatedRecord() throws Exception {
        IocRecord updated = IocRecord.builder()
                .id(1L).value("203.0.113.5").type("IP").source("AbuseIPDB")
                .status("RANKED").severityScore(85).severity("CRITICAL").countryCode("US").build();
        when(processingService.updateSeverity(1L, 85, "US", 10)).thenReturn(updated);

        mockMvc.perform(patch("/api/v1/processing/iocs/1/severity")
                        .param("score", "85")
                        .param("countryCode", "US")
                        .param("reportCount", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("RANKED"))
                .andExpect(jsonPath("$.severityScore").value(85))
                .andExpect(jsonPath("$.severity").value("CRITICAL"));
    }

    @Test
    @DisplayName("GET /api/v1/processing/stats returns all count fields")
    void getStats_returnsAllFields() throws Exception {
        when(iocRepository.count()).thenReturn(100L);
        when(iocRepository.countByType("IP")).thenReturn(60L);
        when(iocRepository.countByType("DOMAIN")).thenReturn(40L);
        when(iocRepository.countByStatus("PENDING")).thenReturn(5L);
        when(iocRepository.countByStatus("VALIDATED")).thenReturn(20L);
        when(iocRepository.countByStatus("RANKED")).thenReturn(75L);
        when(iocRepository.countBySeverity("CRITICAL")).thenReturn(10L);
        when(iocRepository.countBySeverity("HIGH")).thenReturn(20L);
        when(iocRepository.countBySeverity("MEDIUM")).thenReturn(25L);
        when(iocRepository.countBySeverity("LOW")).thenReturn(20L);

        mockMvc.perform(get("/api/v1/processing/stats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(100))
                .andExpect(jsonPath("$.ips").value(60))
                .andExpect(jsonPath("$.ranked").value(75));
    }
}
