package com.treath.processing.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * IocRecord – JPA entity stored in MySQL table "ioc_records".
 *
 * Represents a single Indicator of Compromise (IOC) enriched with:
 *   - type         : IP or DOMAIN
 *   - source       : AbuseIPDB | AlienVault
 *   - status       : PENDING → VALIDATED → RANKED → FAILED
 *   - severityScore: 0–100 from the Ranking Service (AbuseIPDB confidence)
 *   - severity     : LOW | MEDIUM | HIGH | CRITICAL derived from score
 */
@Entity
@Table(name = "ioc_records",
       uniqueConstraints = @UniqueConstraint(columnNames = {"value", "source"}))
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IocRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** The raw IOC value – IP address or domain name */
    @Column(nullable = false, length = 255)
    private String value;

    /** IOC type: IP or DOMAIN */
    @Column(nullable = false, length = 20)
    private String type;

    /** Originating threat-intelligence source */
    @Column(nullable = false, length = 50)
    private String source;

    /**
     * Processing state machine:
     *   PENDING   → received from extraction
     *   VALIDATED → passed basic format checks
     *   RANKED    → severity score assigned by Ranking Service
     *   FAILED    → rejected (invalid format / ranking error)
     */
    @Column(nullable = false, length = 20)
    @Builder.Default
    private String status = "PENDING";

    /** Abuse confidence score (0–100) from AbuseIPDB check endpoint */
    @Builder.Default
    private Integer severityScore = 0;

    /**
     * Human-readable severity label derived from score:
     *   0–25   → LOW
     *   26–50  → MEDIUM
     *   51–75  → HIGH
     *   76–100 → CRITICAL
     */
    @Column(length = 20)
    @Builder.Default
    private String severity = "UNKNOWN";

    /** Country code from AbuseIPDB (IPs only) */
    @Column(length = 5)
    private String countryCode;

    /** Number of times this IOC has been reported */
    @Builder.Default
    private Integer reportCount = 0;

    @Column(nullable = false, updatable = false)
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    @Builder.Default
    private LocalDateTime updatedAt = LocalDateTime.now();

    @PreUpdate
    public void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }
}
