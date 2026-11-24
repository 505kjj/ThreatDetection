package com.example.threatdetection.monitoring;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import jakarta.annotation.PreDestroy;
import org.flywaydb.core.Flyway;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static com.example.threatdetection.monitoring.MonitoringSignal.Action;

@Repository
@EnableConfigurationProperties(MonitoringProperties.class)
class MonitoringEventRepository {
    private static final RowMapper<MonitoringEvent> EVENT = (row, index) -> new MonitoringEvent(
            row.getString("client_id"), row.getObject("event_id", UUID.class),
            row.getObject("received_at", OffsetDateTime.class).toInstant(),
            row.getObject("detected_at", OffsetDateTime.class).toInstant(),
            row.getBoolean("synthetic"), MonitoringSignal.valueOf(row.getString("signal")),
            Action.valueOf(row.getString("action")));

    private final HikariDataSource source;
    private final JdbcTemplate jdbc;

    MonitoringEventRepository(MonitoringProperties properties) {
        HikariConfig pool = new HikariConfig();
        pool.setPoolName("monitoring-store");
        pool.setJdbcUrl(databaseUrl(properties.storePath()));
        pool.setUsername("sa");
        pool.setMinimumIdle(1);
        pool.setMaximumPoolSize(3);
        pool.setConnectionTimeout(2000);
        source = new HikariDataSource(pool);
        try {
            Flyway.configure().dataSource(source).locations("classpath:db/monitoring").load().migrate();
        } catch (RuntimeException error) {
            source.close();
            throw error;
        }
        jdbc = new JdbcTemplate(source);
        jdbc.setQueryTimeout(3);
    }

    private static String databaseUrl(String setting) {
        if (setting == null || setting.isBlank()) return "jdbc:h2:mem:monitoring-" + UUID.randomUUID();
        Path path = Path.of(setting).normalize();
        if (!path.isAbsolute() || setting.matches("(?s).*[;\\r\\n].*") || !Files.isDirectory(path.getParent())) {
            throw new IllegalArgumentException("Monitoring storage requires an absolute database base path in an existing directory");
        }
        return "jdbc:h2:file:" + path.toString().replace('\\', '/') + ";WRITE_DELAY=0";
    }

    @PreDestroy
    void close() {
        source.close();
    }

    Optional<MonitoringEvent> findByClientIdAndEventId(String clientId, UUID eventId) {
        return jdbc.query("select * from monitoring_event where client_id = ? and event_id = ?",
                EVENT, clientId, eventId).stream().findFirst();
    }

    void save(MonitoringEvent event) {
        jdbc.update("""
                insert into monitoring_event (client_id, event_id, received_at, detected_at, synthetic, signal, action)
                values (?, ?, ?, ?, ?, ?, ?)
                """, event.clientId(), event.eventId(), sqlTime(event.receivedAt()), sqlTime(event.detectedAt()),
                event.synthetic(), event.signal().name(), event.action().name());
    }

    List<MonitoringEvent> recent(boolean synthetic, Instant cutoff) {
        return jdbc.query("""
                select * from monitoring_event where synthetic = ? and received_at >= ?
                order by received_at desc, id desc fetch first 20 rows only
                """, EVENT, synthetic, sqlTime(cutoff));
    }

    record Count(MonitoringSignal signal, Action action, long total) {}

    List<Count> countActions(boolean synthetic, Instant cutoff) {
        return jdbc.query("""
                select signal, action, count(*) as total from monitoring_event
                where synthetic = ? and received_at >= ? group by signal, action
                """, (row, index) -> new Count(MonitoringSignal.valueOf(row.getString("signal")),
                Action.valueOf(row.getString("action")), row.getLong("total")), synthetic, sqlTime(cutoff));
    }

    void purge(Instant cutoff) {
        jdbc.update("delete from monitoring_event where received_at < ?", sqlTime(cutoff));
    }

    private static OffsetDateTime sqlTime(Instant instant) {
        return instant.atOffset(ZoneOffset.UTC);
    }
}
