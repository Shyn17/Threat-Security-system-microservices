package com.treath.processing.repository;

import com.treath.processing.model.IocRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * IocRepository – Spring Data JPA repository for IocRecord.
 */
@Repository
public interface IocRepository extends JpaRepository<IocRecord, Long> {

    Optional<IocRecord> findByValueAndSource(String value, String source);

    List<IocRecord> findByType(String type);

    List<IocRecord> findByStatus(String status);

    List<IocRecord> findBySeverity(String severity);

    List<IocRecord> findBySource(String source);

    List<IocRecord> findBySeverityScoreGreaterThanEqual(Integer score);

    @Query("SELECT r FROM IocRecord r ORDER BY r.severityScore DESC")
    List<IocRecord> findAllOrderedBySeverityDesc();

    @Query("SELECT r FROM IocRecord r WHERE r.status = 'RANKED' ORDER BY r.severityScore DESC")
    List<IocRecord> findRankedOrderedBySeverityDesc();

    long countByStatus(String status);

    long countBySeverity(String severity);

    long countByType(String type);
}
