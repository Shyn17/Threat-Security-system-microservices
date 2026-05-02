package com.threat.ranking.controller;

import com.threat.ranking.service.RankingService;
import com.threat.ranking.service.RankingService.RankResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(RankingController.class)
@DisplayName("RankingController Web Layer Tests")
class RankingControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private RankingService rankingService;

    @Test
    @DisplayName("GET /api/v1/rank/health returns 200 with status UP")
    void health_returns200() throws Exception {
        mockMvc.perform(get("/api/v1/rank/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.service").value("ranking-service"));
    }

    @Test
    @DisplayName("POST /api/v1/rank ranks an IOC and returns full result")
    void rank_returns200WithResult() throws Exception {
        RankResult mockResult = new RankResult(85, "CRITICAL", 30, "CN");
        when(rankingService.rank(1L, "203.0.113.5", "IP")).thenReturn(mockResult);

        mockMvc.perform(post("/api/v1/rank")
                        .param("iocId", "1")
                        .param("value", "203.0.113.5")
                        .param("type",  "IP"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.iocId").value(1))
                .andExpect(jsonPath("$.score").value(85))
                .andExpect(jsonPath("$.severity").value("CRITICAL"))
                .andExpect(jsonPath("$.countryCode").value("CN"))
                .andExpect(jsonPath("$.reportCount").value(30));
    }

    @Test
    @DisplayName("GET /api/v1/rank/check/ip performs ad-hoc IP check")
    void checkIp_returns200() throws Exception {
        RankResult mockResult = new RankResult(40, "MEDIUM", 5, "DE");
        when(rankingService.rank(-1L, "8.8.8.8", "IP")).thenReturn(mockResult);

        mockMvc.perform(get("/api/v1/rank/check/ip").param("ip", "8.8.8.8"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ip").value("8.8.8.8"))
                .andExpect(jsonPath("$.score").value(40))
                .andExpect(jsonPath("$.severity").value("MEDIUM"));
    }

    @Test
    @DisplayName("GET /api/v1/rank/check/domain performs ad-hoc domain check")
    void checkDomain_returns200() throws Exception {
        RankResult mockResult = new RankResult(65, "HIGH", 0, "");
        when(rankingService.rank(-1L, "evil.xyz", "DOMAIN")).thenReturn(mockResult);

        mockMvc.perform(get("/api/v1/rank/check/domain").param("domain", "evil.xyz"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.domain").value("evil.xyz"))
                .andExpect(jsonPath("$.score").value(65))
                .andExpect(jsonPath("$.severity").value("HIGH"));
    }
}
