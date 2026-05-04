package com.example.threatdetection.repository;

import com.example.threatdetection.model.RiskLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RiskLogRepository extends JpaRepository<RiskLog, Long> {

    List<RiskLog> findTop100ByOrderByCreatedAtDesc();

    List<RiskLog> findBySessionIdOrderByCreatedAtDesc(String sessionId);

    List<RiskLog> findBySessionIdOrderByCreatedAtAsc(String sessionId);

    List<RiskLog> findByRiskLevelOrderByCreatedAtDesc(String riskLevel);

    List<RiskLog> findByDomainContainingIgnoreCaseOrderByCreatedAtDesc(String domain);

    @Query("SELECT r FROM RiskLog r WHERE " +
           "(:riskLevel IS NULL OR r.riskLevel = :riskLevel) AND " +
           "(:domain IS NULL OR LOWER(r.domain) LIKE LOWER(CONCAT('%', :domain, '%'))) AND " +
           "(:search IS NULL OR LOWER(r.sessionId) LIKE LOWER(CONCAT('%', :search, '%')) OR " +
           "LOWER(r.domain) LIKE LOWER(CONCAT('%', :search, '%'))) " +
           "ORDER BY r.createdAt DESC")
    List<RiskLog> findFiltered(@Param("riskLevel") String riskLevel,
                               @Param("domain") String domain,
                               @Param("search") String search);

    long countByRiskLevel(String riskLevel);
}
