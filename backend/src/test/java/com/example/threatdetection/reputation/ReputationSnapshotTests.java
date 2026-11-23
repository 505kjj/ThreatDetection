package com.example.threatdetection.reputation;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ReputationSnapshotTests {
    private final Instant time = Instant.parse("2026-01-01T00:00:00Z");
    private final ReputationSnapshot snapshot = new FixtureReputationProvider(time, time.plusSeconds(10))
            .current().orElseThrow();

    @Test
    void matchesOnlyExactHostAndDoesNotBroadenPathIndicators() {
        assertThat(snapshot.confirmsHost(FixtureReputationProvider.PHISH)).isTrue();
        assertThat(snapshot.confirmsHost("sub." + FixtureReputationProvider.PHISH)).isFalse();
        assertThat(snapshot.confirmsHost(FixtureReputationProvider.SAFE)).isFalse();
        assertThat(snapshot.confirmsHost("shared.example.test")).isFalse();
    }

    @Test
    void rejectsExpiredAndFutureDatedData() {
        assertThat(snapshot.isCurrent(time)).isTrue();
        assertThat(snapshot.isCurrent(time.plusSeconds(10))).isFalse();
        assertThat(snapshot.isCurrent(time.minusSeconds(61))).isFalse();
    }

    @Test
    void rejectsRawUrlsWildcardsAndDuplicateIndicators() {
        for (String host : List.of("https://example.test/login?private=1", "*.example.test", "EXAMPLE.TEST")) {
            assertThatThrownBy(() -> new ReputationSnapshot.Entry(ReputationSnapshot.Kind.HOST, host,
                    ReputationSnapshot.Threat.PHISHING)).isInstanceOf(IllegalArgumentException.class);
        }
        var entry = snapshot.entries().getFirst();
        assertThatThrownBy(() -> new ReputationSnapshot(time, time.plusSeconds(10), List.of(entry, entry)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void explicitNetworkPathsRequireCanonicalUrlsWithoutSensitiveComponents() {
        var path = new ReputationSnapshot.Entry(ReputationSnapshot.Kind.URL_PATH,
                "http://127.0.0.1:9000/Fixture/download", ReputationSnapshot.Threat.MALWARE);
        assertThat(new ReputationSnapshot(time, time.plusSeconds(10), List.of(path))
                .confirmsHost("127.0.0.1")).isFalse();
        for (String value : List.of("https://example.test", "https://user@example.test/fixture",
                "https://example.test/fixture?token=private", "https://example.test/fixture#secret",
                "https://example.test:443/fixture", "http://127.01/fixture", "https://example.test/a/../fixture",
                "https://example.test/%2E/fixture", "https://example.test/fixture*")) {
            assertThatThrownBy(() -> new ReputationSnapshot.Entry(ReputationSnapshot.Kind.URL_PATH, value,
                    ReputationSnapshot.Threat.MALWARE)).isInstanceOf(IllegalArgumentException.class);
        }
    }
}
