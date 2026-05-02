package com.threat.database.repository;

import com.threat.database.model.IocRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface IocRepository extends JpaRepository<IocRecord, Long> {

    List<IocRecord> findByType(String type);
    List<IocRecord> findByStatus(String status);
    List<IocRecord> findBySeverity(String severity);
    List<IocRecord> findBySource(String source);
    List<IocRecord> findByCountryCode(String countryCode);

    List<IocRecord> findBySeverityScoreGreaterThanEqual(Integer score);

    @Query("SELECT r FROM IocRecord r WHERE r.status = 'RANKED' ORDER BY r.severityScore DESC")
    List<IocRecord> findRankedOrderedBySeverityDesc();

    @Query("SELECT r FROM IocRecord r ORDER BY r.severityScore DESC")
    List<IocRecord> findAllOrderedBySeverityDesc();

    @Query("SELECT r FROM IocRecord r WHERE r.createdAt >= :since ORDER BY r.createdAt DESC")
    List<IocRecord> findSince(LocalDateTime since);

    // Count-based analytics
    long countByType(String type);
    long countByStatus(String status);
    long countBySeverity(String severity);
    long countBySource(String source);
}
