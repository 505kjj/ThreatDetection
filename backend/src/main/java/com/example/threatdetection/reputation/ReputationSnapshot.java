package com.example.threatdetection.reputation;

import com.example.threatdetection.dto.ApiFields;
import com.fasterxml.jackson.annotation.JsonFormat;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

public record ReputationSnapshot(
        @JsonFormat(shape = JsonFormat.Shape.STRING) Instant generatedAt,
        @JsonFormat(shape = JsonFormat.Shape.STRING) Instant expiresAt,
        List<Entry> entries) {

    static final int MAX_ENTRIES = 20_000;
    private static final Comparator<Entry> ORDER = Comparator.comparing(Entry::kind).thenComparing(Entry::value);

    public ReputationSnapshot {
        Objects.requireNonNull(generatedAt);
        Objects.requireNonNull(expiresAt);
        Objects.requireNonNull(entries);
        if (!expiresAt.isAfter(generatedAt) || Duration.between(generatedAt, expiresAt).compareTo(Duration.ofDays(1)) > 0
                || entries.size() > MAX_ENTRIES) {
            throw new IllegalArgumentException("Invalid reputation snapshot bounds");
        }
        entries = entries.stream().sorted(ORDER).toList();
        for (int i = 1; i < entries.size(); i++) {
            if (ORDER.compare(entries.get(i - 1), entries.get(i)) == 0) {
                throw new IllegalArgumentException("Duplicate reputation indicator");
            }
        }
    }

    public boolean isCurrent(Instant now) {
        return !generatedAt.isAfter(now.plusSeconds(60)) && expiresAt.isAfter(now);
    }

    public boolean confirmsHost(String hostname) {
        String host = hostname.toLowerCase(Locale.ROOT);
        int low = 0;
        int high = entries.size() - 1;
        while (low <= high) {
            int middle = (low + high) >>> 1;
            Entry candidate = entries.get(middle);
            int comparison = candidate.kind() == Kind.HOST ? candidate.value().compareTo(host) : 1;
            if (comparison == 0) return true;
            if (comparison < 0) low = middle + 1;
            else high = middle - 1;
        }
        return false;
    }

    public enum Kind { HOST, URL_SHA256, URL_PATH }
    public enum Threat { PHISHING, MALWARE }

    public record Entry(Kind kind, String value, Threat threat) {
        public Entry {
            Objects.requireNonNull(kind);
            Objects.requireNonNull(value);
            Objects.requireNonNull(threat);
            boolean valid = switch (kind) {
                case HOST -> value.equals(value.toLowerCase(Locale.ROOT)) && value.matches(ApiFields.HOST);
                case URL_SHA256 -> value.matches("[0-9a-f]{64}");
                case URL_PATH -> validPathIndicator(value);
            };
            if (!valid) throw new IllegalArgumentException("Invalid reputation indicator");
        }

        private static boolean validPathIndicator(String value) {
            if (value.length() > 512 || !value.matches("https?://[a-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._~/-]*")) {
                return false;
            }
            URI uri = URI.create(value);
            String host = uri.getHost();
            int port = uri.getPort();
            if (host == null || !host.matches(ApiFields.HOST) || port > 65535 ||
                    ("https".equals(uri.getScheme()) ? port == 443 : port == 80)) {
                return false;
            }
            String authority = host + (port < 0 ? "" : ":" + port);
            return authority.equals(uri.getRawAuthority()) &&
                    Arrays.stream(uri.getRawPath().split("/"))
                            .noneMatch(segment -> segment.equals(".") || segment.equals("..")) &&
                    canonicalAddress(host);
        }

        private static boolean canonicalAddress(String host) {
            if (!host.matches("[0-9.]+")) return true;
            String[] octets = host.split("\\.");
            return octets.length == 4 && Arrays.stream(octets).allMatch(octet ->
                    octet.matches("0|[1-9][0-9]{0,2}") && Integer.parseInt(octet) <= 255);
        }
    }
}
