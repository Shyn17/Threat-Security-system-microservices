package com.threat.database.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * IocRecord – mirror of the entity in the Processing Service.
 * The Database Service shares the same MySQL table "ioc_records"
 * but provides a dedicated read/query interface.
 */
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

    @Column(nullable = false, length = 255)
    private String value;

    @Column(nullable = false, length = 20)
    private String type;

    @Column(nullable = false, length = 50)
    private String source;

    @Column(nullable = false, length = 20)
    private String status;

    private Integer severityScore;

    @Column(length = 20)
    private String severity;

    @Column(length = 5)
    private String countryCode;

    private Integer reportCount;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
