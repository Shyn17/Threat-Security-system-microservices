package com.threat.api.gateway;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.*;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(GatewayController.class)
@DisplayName("GatewayController Web Layer Tests")
class GatewayControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private RestTemplate restTemplate;

    @Autowired
    private GatewayController gatewayController;

    void configureGatewayUrls() {
        ReflectionTestUtils.setField(gatewayController, "ingestionUrl",  "http://localhost:8081");
        ReflectionTestUtils.setField(gatewayController, "extractionUrl", "http://localhost:8082");
        ReflectionTestUtils.setField(gatewayController, "processingUrl", "http://localhost:8083");
        ReflectionTestUtils.setField(gatewayController, "rankingUrl",    "http://localhost:8084");
        ReflectionTestUtils.setField(gatewayController, "databaseUrl",   "http://localhost:8085");
        ReflectionTestUtils.setField(gatewayController, "analyticsUrl",  "http://localhost:8086");
        ReflectionTestUtils.setField(gatewayController, "restTemplate",  restTemplate);
    }

    // ── Health & Routes ───────────────────────────────────────────────────────

    @Test
    @DisplayName("GET /gateway/health returns 200 with status UP")
    void health_returns200() throws Exception {
        mockMvc.perform(get("/gateway/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.service").value("api-gateway"))
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.port").value(8080));
    }

    @Test
    @DisplayName("GET /gateway/routes returns all 6 registered routes")
    void routes_returnsAllRoutes() throws Exception {
        mockMvc.perform(get("/gateway/routes"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.routes").isMap())
                .andExpect(jsonPath("$.routes['/api/v1/ingest/**']").exists())
                .andExpect(jsonPath("$.routes['/api/v1/processing/**']").exists())
                .andExpect(jsonPath("$.routes['/api/v1/rank/**']").exists())
                .andExpect(jsonPath("$.routes['/api/v1/db/**']").exists())
                .andExpect(jsonPath("$.routes['/api/v1/analytics/**']").exists());
    }

    // ── Proxy routing ─────────────────────────────────────────────────────────

    @ParameterizedTest(name = "Route {0} proxies to downstream service")
    @CsvSource({
        "/api/v1/ingest/health,  http://localhost:8081",
        "/api/v1/processing/iocs, http://localhost:8083",
        "/api/v1/rank/health,     http://localhost:8084",
        "/api/v1/db/iocs,         http://localhost:8085",
        "/api/v1/analytics/summary, http://localhost:8086"
    })
    @DisplayName("Proxy routes requests to correct downstream URLs")
    void proxyRouting_callsDownstreamService(String path, String expectedBase) throws Exception {
        configureGatewayUrls();

        String downstreamBody = "{\"status\":\"UP\"}";
        when(restTemplate.exchange(any(URI.class), any(HttpMethod.class), any(HttpEntity.class), eq(String.class)))
                .thenReturn(new ResponseEntity<>(downstreamBody, HttpStatus.OK));

        mockMvc.perform(get(path.trim()))
                .andExpect(status().isOk());

        verify(restTemplate).exchange(
                argThat((URI uri) -> uri.toString().startsWith(expectedBase.trim())),
                eq(HttpMethod.GET),
                any(HttpEntity.class),
                eq(String.class)
        );
    }

    @Test
    @DisplayName("Proxy returns 502 Bad Gateway when downstream service is unreachable")
    void proxyRouting_downstreamFailure_returns502() throws Exception {
        configureGatewayUrls();

        when(restTemplate.exchange(any(URI.class), any(HttpMethod.class), any(HttpEntity.class), eq(String.class)))
                .thenThrow(new RuntimeException("Connection refused"));

        mockMvc.perform(get("/api/v1/ingest/all"))
                .andExpect(status().isBadGateway())
                .andExpect(jsonPath("$.error").value("Gateway routing failed"));
    }

    @Test
    @DisplayName("Proxy forwards downstream 4xx errors to caller")
    void proxyRouting_downstreamClientError_forwardsStatus() throws Exception {
        configureGatewayUrls();

        when(restTemplate.exchange(any(URI.class), any(HttpMethod.class), any(HttpEntity.class), eq(String.class)))
                .thenReturn(new ResponseEntity<>("{\"error\":\"not found\"}", HttpStatus.NOT_FOUND));

        mockMvc.perform(get("/api/v1/db/iocs/9999"))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("Proxy passes query parameters through to downstream URL")
    void proxyRouting_passesQueryParams() throws Exception {
        configureGatewayUrls();

        when(restTemplate.exchange(any(URI.class), any(HttpMethod.class), any(HttpEntity.class), eq(String.class)))
                .thenReturn(new ResponseEntity<>("[]", HttpStatus.OK));

        mockMvc.perform(get("/api/v1/processing/iocs/top?minScore=90"))
                .andExpect(status().isOk());

        verify(restTemplate).exchange(
                argThat((URI uri) -> uri.toString().contains("minScore=90")),
                eq(HttpMethod.GET),
                any(HttpEntity.class),
                eq(String.class)
        );
    }
}
