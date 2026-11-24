package com.example.threatdetection.monitoring;

import com.example.threatdetection.config.ApiSecurityProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.example.threatdetection.config.ApiSecurityProperties.Role.BROWSER;
import static com.example.threatdetection.monitoring.MonitoringSignal.Action;
import static com.example.threatdetection.monitoring.MonitoringSignal.Category;

@Service
@EnableConfigurationProperties(MonitoringProperties.class)
class MonitoringService {
    private static final Duration STATUS_LIFETIME = Duration.ofMinutes(3);
    private static final Duration MAX_EVENT_AGE = Duration.ofMinutes(5);
    private static final int HEARTBEATS_PER_MINUTE = 12;

    private final MonitoringEventRepository repository;
    private final MonitoringProperties properties;
    private final Map<String, BrowserState> activeClients = new HashMap<>();

    MonitoringService(MonitoringEventRepository repository, MonitoringProperties properties,
                      ApiSecurityProperties credentials) {
        this.repository = repository;
        this.properties = properties;
        for (String id : properties.syntheticClients()) {
            var client = credentials.clients().get(id);
            if (client == null || client.role() != BROWSER) {
                throw new IllegalArgumentException("Synthetic monitoring clients must be configured browser clients");
            }
        }
    }

    synchronized void heartbeat(String client, Protection protection) {
        Instant now = Instant.now();
        BrowserState state = stateFor(client, now);
        if (++state.heartbeats > HEARTBEATS_PER_MINUTE) throw tooMany();
        state.contact = now;
        state.protection = protection;
    }

    synchronized void record(String client, MonitoringController.Event request) {
        Instant now = Instant.now();
        BrowserState state = stateFor(client, now);
        if (++state.submissions > properties.eventsPerMinute()) throw tooMany();
        if (!state.fresh(now)) throw new ResponseStatusException(HttpStatus.PRECONDITION_FAILED);

        var signal = parse(MonitoringSignal.class, request.signal());
        var action = parse(Action.class, request.action());
        Instant detected;
        try {
            detected = Instant.parse(request.detectedAt());
        } catch (DateTimeParseException ex) {
            throw badRequest();
        }
        if (!signal.permits(action) || detected.isBefore(now.minus(MAX_EVENT_AGE)) ||
                detected.isAfter(now.plusSeconds(30))) throw badRequest();

        UUID id = UUID.fromString(request.id());
        var existing = repository.findByClientIdAndEventId(client, id);
        if (existing.isPresent()) {
            requireSame(existing.get(), detected, signal, action);
            return;
        }
        try {
            repository.saveAndFlush(new MonitoringEvent(client, id, now, detected,
                    properties.syntheticClients().contains(client), signal, action));
        } catch (DataIntegrityViolationException ex) {
            // The unique constraint arbitrates requests reaching separate backend processes.
            var concurrent = repository.findByClientIdAndEventId(client, id).orElseThrow(() -> ex);
            requireSame(concurrent, detected, signal, action);
        }
    }

    private static void requireSame(MonitoringEvent event, Instant detected, MonitoringSignal signal, Action action) {
        if (!event.matches(detected, signal, action)) throw new ResponseStatusException(HttpStatus.CONFLICT);
    }

    synchronized Dashboard dashboard(boolean synthetic) {
        Instant now = Instant.now();
        Instant cutoff = cutoff(now);
        var categories = new EnumMap<Category, Long>(Category.class);
        for (Category category : Category.values()) categories.put(category, 0L);
        long blocked = 0;
        long warned = 0;
        long bypassed = 0;
        for (var row : repository.countActions(synthetic, cutoff)) {
            switch (row.getAction()) {
                case BLOCKED -> blocked += row.getTotal();
                case WARNED -> warned += row.getTotal();
                case BYPASSED -> bypassed += row.getTotal();
            }
            if (row.getAction() != Action.BYPASSED) categories.merge(row.getSignal().category, row.getTotal(), Long::sum);
        }
        var status = new EnumMap<Protection, Integer>(Protection.class);
        for (Protection protection : Protection.values()) status.put(protection, 0);
        Instant lastContact = null;
        for (var entry : activeClients.entrySet()) {
            var state = entry.getValue();
            if (properties.syntheticClients().contains(entry.getKey()) != synthetic || !state.fresh(now)) continue;
            status.merge(state.protection, 1, Integer::sum);
            if (lastContact == null || state.contact.isAfter(lastContact)) lastContact = state.contact;
        }
        var history = repository.findTop20BySyntheticAndReceivedAtGreaterThanEqualOrderByReceivedAtDescIdDesc(
                synthetic, cutoff).stream().map(MonitoringEvent::entry).toList();
        return new Dashboard(synthetic, properties.retentionDays(), blocked + warned, blocked, warned, bypassed,
                categories, status, lastContact, history);
    }

    @Scheduled(fixedDelay = 3600000, initialDelay = 0)
    synchronized void purgeExpired() {
        repository.purge(cutoff(Instant.now()));
    }

    private Instant cutoff(Instant now) {
        return now.minus(Duration.ofDays(properties.retentionDays()));
    }

    private BrowserState stateFor(String client, Instant now) {
        BrowserState state = activeClients.computeIfAbsent(client, ignored -> new BrowserState());
        if (state.windowStart == null || !now.isBefore(state.windowStart.plusSeconds(60))) {
            state.windowStart = now;
            state.heartbeats = 0;
            state.submissions = 0;
        }
        return state;
    }

    static <T extends Enum<T>> T parse(Class<T> type, String value) {
        try {
            return Enum.valueOf(type, value);
        } catch (IllegalArgumentException ex) {
            throw badRequest();
        }
    }

    private static ResponseStatusException badRequest() { return new ResponseStatusException(HttpStatus.BAD_REQUEST); }
    private static ResponseStatusException tooMany() { return new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS); }

    private static final class BrowserState {
        private Instant windowStart;
        private int heartbeats;
        private int submissions;
        private Instant contact;
        private Protection protection;

        private boolean fresh(Instant now) {
            return contact != null && contact.isAfter(now.minus(STATUS_LIFETIME));
        }
    }

    enum Protection { REPUTATION_AVAILABLE, REPUTATION_UNAVAILABLE }

    record Entry(Instant detectedAt, Category category, MonitoringSignal.Severity severity,
                 MonitoringSignal.Source source, Action action, String reason) {}
    record Dashboard(boolean synthetic, int retentionDays, long total, long blocked, long warned, long bypassed,
                     Map<Category, Long> categories, Map<Protection, Integer> clientStatus, Instant lastContact,
                     List<Entry> recent) {}
}
