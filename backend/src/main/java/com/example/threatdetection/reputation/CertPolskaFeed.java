package com.example.threatdetection.reputation;

import com.example.threatdetection.dto.ApiFields;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.IDN;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/** Pulls the CERT Polska v2 export. Indicator destinations are never requested. */
@Component
@ConditionalOnProperty(name = "threat.reputation.ingestion.enabled", havingValue = "true")
final class CertPolskaFeed implements ThreatFeed {
    static final URI ENDPOINT = URI.create("https://hole.cert.pl/domains/v2/domains.csv");
    private static final int MAX_SOURCE_BYTES = 64 * 1024 * 1024;
    private static final int MAX_SOURCE_ROWS = 1_000_000;
    private static final Pattern HOST = Pattern.compile(ApiFields.HOST);
    private static final Pattern HEADER = Pattern.compile("[\\p{L}_][\\p{L}\\p{N}_ ]{0,63}");
    private static final Comparator<Observation> ORDER =
            Comparator.comparing(Observation::insertedAt).thenComparingLong(Observation::id);
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NEVER).build();

    @Override
    public Result fetch(Instant now) throws IOException {
        HttpRequest request = HttpRequest.newBuilder(ENDPOINT)
                .header("Accept", "application/octet-stream, text/plain, text/tab-separated-values")
                .header("User-Agent", "ThreatDetection reputation ingestion")
                .timeout(Duration.ofSeconds(45))
                .GET().build();
        var response = http.sendAsync(request, ignored -> new BoundedBody());
        HttpResponse<byte[]> downloaded;
        try {
            downloaded = response.get(45, TimeUnit.SECONDS);
        } catch (InterruptedException interrupted) {
            response.cancel(true);
            Thread.currentThread().interrupt();
            throw new IOException("Reputation feed download interrupted", interrupted);
        } catch (ExecutionException | TimeoutException failure) {
            response.cancel(true);
            throw new IOException("Reputation feed download failed", failure);
        }
        if (downloaded.statusCode() != 200) throw new IOException("Reputation feed did not return a complete export");

        Instant sourceTime;
        try {
            sourceTime = sourceTimestamp(downloaded.headers().firstValue("Last-Modified").orElseThrow(),
                    downloaded.headers().firstValue("Date").orElseThrow(),
                    downloaded.headers().firstValue("Age").orElse("0"), now);
        } catch (RuntimeException failure) {
            throw new IOException("Reputation feed freshness metadata is invalid");
        }
        return parse(downloaded.body(), sourceTime, now);
    }

    static Instant sourceTimestamp(String lastModified, String date, String ageHeader, Instant now) {
        var time = httpDate(lastModified);
        var responseDate = httpDate(date);
        long age = Long.parseLong(ageHeader);
        if (age < 0 || responseDate.isAfter(now.plusSeconds(60)) ||
                time.isAfter(responseDate.plusSeconds(60))) {
            throw new IllegalArgumentException("Invalid feed age");
        }
        Instant cacheStart = now.minusSeconds(age);
        return time.isBefore(cacheStart) ? time : cacheStart;
    }

    private static Instant httpDate(String value) {
        return ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
    }

    static Result parse(byte[] body, Instant sourceTime, Instant now) throws IOException {
        Instant expires = sourceTime.plus(ReputationIngestionSettings.MAX_AGE);
        if (sourceTime.isAfter(now.plusSeconds(60)) || !expires.isAfter(now)) {
            throw new IOException("Reputation feed is outside its freshness window");
        }
        var accepted = new HashMap<String, Observation>();
        int rejected = 0;
        int rows = 0;
        var utf8 = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT);
        try (var input = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(body), utf8))) {
            String line;
            while ((line = input.readLine()) != null) {
                if (++rows > MAX_SOURCE_ROWS || line.length() > 2048) throw invalidFeed();
                if (rows == 1 && line.startsWith("\uFEFF")) line = line.substring(1);
                String[] fields = line.split("\t", -1);
                if (fields.length != 4) throw invalidFeed();
                if (rows == 1 && isHeader(fields)) continue;
                Observation item = observation(fields, now);
                if (item.host() == null) {
                    rejected++;
                    continue;
                }
                var previous = accepted.get(item.host());
                if (previous != null && ORDER.compare(previous, item) == 0 &&
                        previous.removed() != item.removed()) throw invalidFeed();
                accepted.merge(item.host(), item, (first, second) -> ORDER.compare(first, second) >= 0 ? first : second);
            }
        }
        int active = 0;
        for (Observation observation : accepted.values()) {
            if (!observation.removed()) active++;
        }
        if (active == 0) throw invalidFeed();
        var selected = accepted.values().stream().filter(item -> !item.removed())
                .sorted(ORDER.reversed().thenComparing(Observation::host))
                .limit(ReputationSnapshot.MAX_ENTRIES)
                .map(item -> new ReputationSnapshot.Entry(ReputationSnapshot.Kind.HOST, item.host(),
                        ReputationSnapshot.Threat.PHISHING))
                .toList();
        return new Result(new ReputationSnapshot(sourceTime, expires, selected), active, rejected);
    }

    private static Observation observation(String[] fields, Instant now) throws IOException {
        try {
            long id = Long.parseLong(fields[0]);
            Instant inserted = OffsetDateTime.parse(fields[2]).toInstant();
            boolean removed = !fields[3].isEmpty() && !fields[3].equals("null");
            if (id < 1 || inserted.isAfter(now.plusSeconds(60))) throw invalidFeed();
            if (removed && OffsetDateTime.parse(fields[3]).toInstant().isBefore(inserted)) throw invalidFeed();
            return new Observation(hostname(fields[1]), id, inserted, removed);
        } catch (RuntimeException failure) {
            throw invalidFeed();
        }
    }

    private static boolean isHeader(String[] fields) {
        for (String field : fields) {
            if (!HEADER.matcher(field).matches()) return false;
        }
        return true;
    }

    private static String hostname(String input) {
        try {
            String host = IDN.toASCII(input.strip().replaceFirst("\\.$", ""), IDN.USE_STD3_ASCII_RULES)
                    .toLowerCase(Locale.ROOT);
            return host.contains(".") && HOST.matcher(host).matches() ? host : null;
        } catch (IllegalArgumentException failure) {
            return null;
        }
    }

    private static IOException invalidFeed() {
        return new IOException("Reputation feed did not contain a valid active TSV export");
    }

    private record Observation(String host, long id, Instant insertedAt, boolean removed) {}

    private static final class BoundedBody implements HttpResponse.BodySubscriber<byte[]> {
        private final HttpResponse.BodySubscriber<byte[]> bytes = HttpResponse.BodySubscribers.ofByteArray();
        private Flow.Subscription subscription;
        private long size;
        private boolean rejected;

        @Override
        public CompletionStage<byte[]> getBody() {
            return bytes.getBody();
        }

        @Override
        public void onSubscribe(Flow.Subscription value) {
            subscription = value;
            bytes.onSubscribe(value);
        }

        @Override
        public void onNext(List<ByteBuffer> incoming) {
            if (rejected) return;
            for (ByteBuffer buffer : incoming) size += buffer.remaining();
            if (size > MAX_SOURCE_BYTES) {
                rejected = true;
                subscription.cancel();
                bytes.onError(new IOException("Reputation feed exceeds the download limit"));
                return;
            }
            bytes.onNext(incoming);
        }

        @Override
        public void onError(Throwable failure) {
            if (!rejected) bytes.onError(failure);
        }

        @Override
        public void onComplete() {
            if (!rejected) bytes.onComplete();
        }
    }
}
