package com.example.threatdetection.reputation;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertPolskaFeedTests {
    private static final Instant NOW = Instant.parse("2026-11-23T14:45:00Z");
    private static final Instant MODIFIED = NOW.minusSeconds(60);
    private static final String TIME = "2026-11-23T12:00:00+00:00";

    @Test
    void normalizesDnsNamesAndDeduplicatesWithRemovalAndReaddition() throws Exception {
        String fixture = "RegisterPositionId\tDomainAddress\tInsertDate\tDeleteDate\n"
                + row(1, "BÜCHER.example.test.", 10, "")
                + row(2, "xn--bcher-kva.example.test", 11, "")
                + row(3, "deleted.example.test", 10, "")
                + row(4, "deleted.example.test", 11, TIME)
                + row(5, "returned.example.test", 10, "2026-11-23T11:00:00+00:00")
                + row(6, "returned.example.test", 12, "")
                + row(7, "*.example.test", 12, "")
                + row(8, "https://shared.example.test/path", 12, "");
        var result = CertPolskaFeed.parse(bytes(fixture), MODIFIED, NOW);
        assertThat(result.activeIndicators()).isEqualTo(2);
        assertThat(result.rejectedIndicators()).isEqualTo(2);
        assertThat(result.snapshot().entries()).extracting(ReputationSnapshot.Entry::value)
                .containsExactly("returned.example.test", "xn--bcher-kva.example.test");
        assertThat(result.snapshot().expiresAt()).isEqualTo(MODIFIED.plus(Duration.ofMinutes(15)));
    }

    @Test
    void keepsNewestTwentyThousandWithStableTieBreaking() throws Exception {
        var rows = new StringBuilder();
        for (int id = 1; id <= 20001; id++) {
            rows.append(id).append("\thost-").append(id).append(".example.test\t").append(TIME).append("\t\n");
        }
        var result = CertPolskaFeed.parse(bytes(rows.toString()), MODIFIED, NOW);
        assertThat(result.activeIndicators()).isEqualTo(20001);
        assertThat(result.snapshot().entries()).hasSize(20000);
        assertThat(result.snapshot().confirmsHost("host-1.example.test")).isFalse();
        assertThat(result.snapshot().confirmsHost("host-20001.example.test")).isTrue();
    }

    @Test
    void rejectsStaleFutureMalformedAndEmptyExports() {
        byte[] valid = bytes("1\tactive.example.test\t" + TIME + "\t\n");
        assertThatThrownBy(() -> CertPolskaFeed.parse(valid, NOW.minusSeconds(900), NOW))
                .isInstanceOf(java.io.IOException.class);
        assertThatThrownBy(() -> CertPolskaFeed.parse(valid, NOW.plusSeconds(61), NOW))
                .isInstanceOf(java.io.IOException.class);
        assertThatThrownBy(() -> CertPolskaFeed.parse(bytes("1\tactive.example.test\tpartial"), MODIFIED, NOW))
                .isInstanceOf(java.io.IOException.class);
        assertThatThrownBy(() -> CertPolskaFeed.parse(bytes("1\tactive.example.test\t" + TIME + "\t" + TIME),
                MODIFIED, NOW)).isInstanceOf(java.io.IOException.class);
    }

    @Test
    void honorsHttpFreshnessWithoutExtendingTheSourceTimestamp() {
        String date = "Mon, 23 Nov 2026 14:45:00 GMT";
        String modified = "Mon, 23 Nov 2026 14:44:00 GMT";
        assertThat(CertPolskaFeed.sourceTimestamp(modified, date, "10", NOW)).isEqualTo(MODIFIED);
        assertThat(CertPolskaFeed.sourceTimestamp(modified, date, "600", NOW)).isEqualTo(NOW.minusSeconds(600));
        assertThatThrownBy(() -> CertPolskaFeed.sourceTimestamp(modified, date, "-1", NOW))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static String row(int id, String host, int hour, String removed) {
        return "%d\t%s\t2026-11-23T%d:00:00+00:00\t%s\n".formatted(id, host, hour, removed);
    }

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
}
