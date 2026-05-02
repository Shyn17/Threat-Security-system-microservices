package com.threat.analytics.repository;

import com.threat.analytics.model.IocRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AnalyticsRepository extends JpaRepository<IocRecord, Long> {

    long countByType(String type);
    long countBySeverity(String severity);
    long countBySource(String source);
    long countByStatus(String status);
    long countByCountryCode(String countryCode);

    @Query("SELECT r.countryCode, COUNT(r) FROM IocRecord r " +
           "WHERE r.countryCode IS NOT NULL AND r.countryCode != '' " +
           "GROUP BY r.countryCode ORDER BY COUNT(r) DESC")
    List<Object[]> countByCountryCodeGrouped();

    @Query("SELECT r.severity, COUNT(r) FROM IocRecord r GROUP BY r.severity")
    List<Object[]> countBySeverityGrouped();

    @Query("SELECT r.source, COUNT(r) FROM IocRecord r GROUP BY r.source")
    List<Object[]> countBySourceGrouped();

    @Query("SELECT r.type, COUNT(r) FROM IocRecord r GROUP BY r.type")
    List<Object[]> countByTypeGrouped();

    @Query("SELECT AVG(r.severityScore) FROM IocRecord r WHERE r.status = 'RANKED'")
    Double avgSeverityScore();

    @Query("SELECT MAX(r.severityScore) FROM IocRecord r")
    Integer maxSeverityScore();

    @Query("SELECT r FROM IocRecord r WHERE r.severityScore >= 75 ORDER BY r.severityScore DESC")
    List<IocRecord> findCriticalAndHighThreats();

    @Query("SELECT r FROM IocRecord r WHERE r.createdAt >= :since ORDER BY r.createdAt DESC")
    List<IocRecord> findSince(LocalDateTime since);
}
