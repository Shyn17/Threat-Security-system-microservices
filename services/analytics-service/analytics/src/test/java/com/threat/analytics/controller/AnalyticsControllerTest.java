package com.threat.analytics.controller;

import com.threat.analytics.model.IocRecord;
import com.threat.analytics.repository.AnalyticsRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.List;

import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AnalyticsController.class)
@DisplayName("AnalyticsController Web Layer Tests")
class AnalyticsControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AnalyticsRepository analyticsRepository;

    @Test
    @DisplayName("GET /api/v1/analytics/health returns 200 with status UP")
    void health_returns200() throws Exception {
        mockMvc.perform(get("/api/v1/analytics/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.service").value("analytics-service"));
    }

    @Test
    @DisplayName("GET /api/v1/analytics/summary returns all summary fields")
    void summary_returnsAllFields() throws Exception {
        when(analyticsRepository.count()).thenReturn(500L);
        when(analyticsRepository.countByType("IP")).thenReturn(300L);
        when(analyticsRepository.countByType("DOMAIN")).thenReturn(200L);
        when(analyticsRepository.countByStatus("RANKED")).thenReturn(400L);
        when(analyticsRepository.countByStatus("PENDING")).thenReturn(50L);
        when(analyticsRepository.countByStatus("VALIDATED")).thenReturn(50L);
        when(analyticsRepository.countBySeverity("CRITICAL")).thenReturn(50L);
        when(analyticsRepository.countBySeverity("HIGH")).thenReturn(100L);
        when(analyticsRepository.countBySeverity("MEDIUM")).thenReturn(150L);
        when(analyticsRepository.countBySeverity("LOW")).thenReturn(100L);
        when(analyticsRepository.avgSeverityScore()).thenReturn(42.5);
        when(analyticsRepository.maxSeverityScore()).thenReturn(100);
        when(analyticsRepository.countBySource("AbuseIPDB")).thenReturn(250L);
        when(analyticsRepository.countBySource("AlienVault")).thenReturn(250L);

        mockMvc.perform(get("/api/v1/analytics/summary"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalIocs").value(500))
                .andExpect(jsonPath("$.totalIps").value(300))
                .andExpect(jsonPath("$.totalDomains").value(200))
                .andExpect(jsonPath("$.ranked").value(400))
                .andExpect(jsonPath("$.critical").value(50))
                .andExpect(jsonPath("$.avgSeverityScore").value(42.5))
                .andExpect(jsonPath("$.abuseipdbCount").value(250));
    }

    @Test
    @DisplayName("GET /api/v1/analytics/by-severity returns severity distribution map")
    void bySeverity_returnsMap() throws Exception {
        when(analyticsRepository.countBySeverityGrouped()).thenReturn(List.of(
                new Object[]{"CRITICAL", 10L},
                new Object[]{"HIGH", 20L},
                new Object[]{"MEDIUM", 30L},
                new Object[]{"LOW", 40L}
        ));

        mockMvc.perform(get("/api/v1/analytics/by-severity"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.CRITICAL").value(10))
                .andExpect(jsonPath("$.HIGH").value(20))
                .andExpect(jsonPath("$.LOW").value(40));
    }

    @Test
    @DisplayName("GET /api/v1/analytics/by-type returns IP vs DOMAIN breakdown")
    void byType_returnsBreakdown() throws Exception {
        when(analyticsRepository.countByTypeGrouped()).thenReturn(List.of(
                new Object[]{"IP", 60L},
                new Object[]{"DOMAIN", 40L}
        ));

        mockMvc.perform(get("/api/v1/analytics/by-type"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.IP").value(60))
                .andExpect(jsonPath("$.DOMAIN").value(40));
    }

    @Test
    @DisplayName("GET /api/v1/analytics/by-source returns source breakdown")
    void bySource_returnsBreakdown() throws Exception {
        when(analyticsRepository.countBySourceGrouped()).thenReturn(List.of(
                new Object[]{"AbuseIPDB", 300L},
                new Object[]{"AlienVault", 200L}
        ));

        mockMvc.perform(get("/api/v1/analytics/by-source"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.AbuseIPDB").value(300))
                .andExpect(jsonPath("$.AlienVault").value(200));
    }

    @Test
    @DisplayName("GET /api/v1/analytics/by-country respects default limit=10")
    void byCountry_defaultLimit() throws Exception {
        when(analyticsRepository.countByCountryCodeGrouped()).thenReturn(List.of(
                new Object[]{"CN", 100L},
                new Object[]{"US", 80L},
                new Object[]{"RU", 60L}
        ));

        mockMvc.perform(get("/api/v1/analytics/by-country"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.CN").value(100))
                .andExpect(jsonPath("$.US").value(80));
    }

    @Test
    @DisplayName("GET /api/v1/analytics/top-threats returns limited list of high-score IOCs")
    void topThreats_returnsLimitedList() throws Exception {
        IocRecord critical = new IocRecord();
        critical.setId(1L);
        critical.setValue("1.2.3.4");
        critical.setType("IP");
        critical.setSource("AbuseIPDB");
        critical.setSeverity("CRITICAL");
        critical.setSeverityScore(95);
        critical.setCountryCode("CN");
        critical.setReportCount(200);
        critical.setCreatedAt(LocalDateTime.now());

        when(analyticsRepository.findCriticalAndHighThreats()).thenReturn(List.of(critical));

        mockMvc.perform(get("/api/v1/analytics/top-threats?limit=5"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].value").value("1.2.3.4"))
                .andExpect(jsonPath("$[0].severity").value("CRITICAL"))
                .andExpect(jsonPath("$[0].severityScore").value(95));
    }

    @Test
    @DisplayName("GET /api/v1/analytics/trend returns count and records for specified hours")
    void trend_returnsCountAndRecords() throws Exception {
        IocRecord recentRecord = new IocRecord();
        recentRecord.setId(2L);
        recentRecord.setValue("5.6.7.8");
        recentRecord.setType("IP");
        recentRecord.setSource("AlienVault");
        recentRecord.setSeverity("HIGH");
        recentRecord.setSeverityScore(70);
        recentRecord.setCreatedAt(LocalDateTime.now().minusHours(2));

        when(analyticsRepository.findSince(any(LocalDateTime.class))).thenReturn(List.of(recentRecord));

        mockMvc.perform(get("/api/v1/analytics/trend?hours=12"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.hours").value(12))
                .andExpect(jsonPath("$.count").value(1))
                .andExpect(jsonPath("$.records[0].value").value("5.6.7.8"));
    }

    @Test
    @DisplayName("GET /api/v1/analytics/trend returns empty records when no recent IOCs")
    void trend_noRecentIocs_returnsZeroCount() throws Exception {
        when(analyticsRepository.findSince(any(LocalDateTime.class))).thenReturn(List.of());

        mockMvc.perform(get("/api/v1/analytics/trend"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.count").value(0))
                .andExpect(jsonPath("$.records").isEmpty());
    }
}
