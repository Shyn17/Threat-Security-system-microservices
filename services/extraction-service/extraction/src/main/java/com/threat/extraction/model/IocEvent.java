package com.threat.extraction.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class IocEvent {

    private String value;     // IP or Domain
    private String type;      // IP / DOMAIN
    private String source;    // AbuseIPDB
}