package com.example.threatdetection.repository;

import com.example.threatdetection.model.BehaviorEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface BehaviorEventRepository extends JpaRepository<BehaviorEvent, Long> {

    List<BehaviorEvent> findBySessionIdOrderByTimestampDesc(String sessionId);
}
