package com.threat.analytics.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.time.LocalDateTime;

/** Shared read-only view of ioc_records table */
@Entity
@Table(name = "ioc_records")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IocRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String value;
    private String type;
    private String source;
    private String status;
    private Integer severityScore;
    private String severity;
    private String countryCode;
    private Integer reportCount;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
