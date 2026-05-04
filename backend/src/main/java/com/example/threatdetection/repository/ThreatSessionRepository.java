package com.example.threatdetection.repository;

import com.example.threatdetection.model.ThreatSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ThreatSessionRepository extends JpaRepository<ThreatSession, Long> {

    Optional<ThreatSession> findBySessionId(String sessionId);
}
