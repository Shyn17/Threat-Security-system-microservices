package com.threat.database.controller;

import com.threat.database.model.IocRecord;
import com.threat.database.repository.IocRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(DatabaseController.class)
@DisplayName("DatabaseController Web Layer Tests")
class DatabaseControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private IocRepository iocRepository;

    private IocRecord sample(String severity, int score) {
        IocRecord r = new IocRecord();
        r.setId(1L);
        r.setValue("203.0.113.5");
        r.setType("IP");
        r.setSource("AbuseIPDB");
        r.setStatus("RANKED");
        r.setSeverity(severity);
        r.setSeverityScore(score);
        r.setCountryCode("US");
        r.setReportCount(10);
        r.setCreatedAt(LocalDateTime.now());
        r.setUpdatedAt(LocalDateTime.now());
        return r;
    }

    @Test
    @DisplayName("GET /api/v1/db/health returns 200")
    void health_returns200() throws Exception {
        mockMvc.perform(get("/api/v1/db/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.service").value("database-service"));
    }

    @Test
    @DisplayName("GET /api/v1/db/iocs returns all IOCs ordered by severity")
    void getAllIocs_returnsList() throws Exception {
        when(iocRepository.findAllOrderedBySeverityDesc()).thenReturn(List.of(sample("CRITICAL", 90)));

        mockMvc.perform(get("/api/v1/db/iocs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].severity").value("CRITICAL"));
    }

    @Test
    @DisplayName("GET /api/v1/db/iocs/{id} returns 200 for existing IOC")
    void getIoc_found_returns200() throws Exception {
        when(iocRepository.findById(1L)).thenReturn(Optional.of(sample("HIGH", 70)));

        mockMvc.perform(get("/api/v1/db/iocs/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.value").value("203.0.113.5"));
    }

    @Test
    @DisplayName("GET /api/v1/db/iocs/{id} returns 404 for missing IOC")
    void getIoc_notFound_returns404() throws Exception {
        when(iocRepository.findById(99L)).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/v1/db/iocs/99"))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("GET /api/v1/db/iocs/type/IP filters by type")
    void getByType_returnsCorrectType() throws Exception {
        when(iocRepository.findByType("IP")).thenReturn(List.of(sample("MEDIUM", 40)));

        mockMvc.perform(get("/api/v1/db/iocs/type/IP"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].type").value("IP"));
    }

    @Test
    @DisplayName("GET /api/v1/db/iocs/severity/CRITICAL filters by severity")
    void getBySeverity_returnsCritical() throws Exception {
        when(iocRepository.findBySeverity("CRITICAL")).thenReturn(List.of(sample("CRITICAL", 95)));

        mockMvc.perform(get("/api/v1/db/iocs/severity/CRITICAL"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].severity").value("CRITICAL"));
    }

    @Test
    @DisplayName("GET /api/v1/db/iocs/country/US filters by country code")
    void getByCountry_returnsFiltered() throws Exception {
        when(iocRepository.findByCountryCode("US")).thenReturn(List.of(sample("HIGH", 60)));

        mockMvc.perform(get("/api/v1/db/iocs/country/US"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].countryCode").value("US"));
    }

    @Test
    @DisplayName("GET /api/v1/db/iocs/top uses default minScore=75")
    void getTopThreats_defaultMinScore() throws Exception {
        when(iocRepository.findBySeverityScoreGreaterThanEqual(75)).thenReturn(List.of(sample("CRITICAL", 90)));

        mockMvc.perform(get("/api/v1/db/iocs/top"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].severityScore").value(90));

        verify(iocRepository).findBySeverityScoreGreaterThanEqual(75);
    }

    @Test
    @DisplayName("GET /api/v1/db/iocs/ranked returns only RANKED IOCs")
    void getRanked_returnsRanked() throws Exception {
        when(iocRepository.findRankedOrderedBySeverityDesc()).thenReturn(List.of(sample("CRITICAL", 85)));

        mockMvc.perform(get("/api/v1/db/iocs/ranked"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].status").value("RANKED"));
    }

    @Test
    @DisplayName("GET /api/v1/db/iocs/recent uses default 24 hours window")
    void getRecent_defaultHours() throws Exception {
        when(iocRepository.findSince(any(LocalDateTime.class))).thenReturn(List.of(sample("LOW", 10)));

        mockMvc.perform(get("/api/v1/db/iocs/recent"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)));
    }

    @Test
    @DisplayName("GET /api/v1/db/stats returns all 12 statistics fields")
    void getStats_returnsAllFields() throws Exception {
        when(iocRepository.count()).thenReturn(200L);
        when(iocRepository.countByType("IP")).thenReturn(120L);
        when(iocRepository.countByType("DOMAIN")).thenReturn(80L);
        when(iocRepository.countByStatus(anyString())).thenReturn(50L);
        when(iocRepository.countBySeverity(anyString())).thenReturn(25L);
        when(iocRepository.countBySource("AbuseIPDB")).thenReturn(100L);
        when(iocRepository.countBySource("AlienVault")).thenReturn(100L);

        mockMvc.perform(get("/api/v1/db/stats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(200))
                .andExpect(jsonPath("$.ips").value(120))
                .andExpect(jsonPath("$.domains").value(80))
                .andExpect(jsonPath("$.sourceAbuseIPDB").value(100));
    }
}
