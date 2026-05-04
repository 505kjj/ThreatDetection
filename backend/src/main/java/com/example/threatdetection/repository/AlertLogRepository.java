package com.example.threatdetection.repository;

import com.example.threatdetection.model.AlertLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AlertLogRepository extends JpaRepository<AlertLog, Long> {

    List<AlertLog> findAllByOrderByCreatedAtDesc();

    List<AlertLog> findByResolvedFalseOrderByCreatedAtDesc();

    List<AlertLog> findTop1ByOrderByCreatedAtDesc();
}
