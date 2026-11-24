package com.example.threatdetection.monitoring;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

interface MonitoringEventRepository extends JpaRepository<MonitoringEvent, Long> {
    Optional<MonitoringEvent> findByClientIdAndEventId(String clientId, UUID eventId);

    List<MonitoringEvent> findTop20BySyntheticAndReceivedAtGreaterThanEqualOrderByReceivedAtDescIdDesc(
            boolean synthetic, Instant cutoff);

    interface Count {
        MonitoringSignal getSignal();
        MonitoringSignal.Action getAction();
        long getTotal();
    }

    @Query("""
            select event.signal as signal, event.action as action, count(event) as total
            from MonitoringEvent event
            where event.synthetic = :synthetic and event.receivedAt >= :cutoff
            group by event.signal, event.action
            """)
    List<Count> countActions(boolean synthetic, Instant cutoff);

    @Modifying
    @Transactional
    @Query("delete from MonitoringEvent event where event.receivedAt < :cutoff")
    int purge(Instant cutoff);
}
