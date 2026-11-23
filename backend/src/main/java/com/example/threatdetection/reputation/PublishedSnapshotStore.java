package com.example.threatdetection.reputation;

import static java.nio.file.StandardCopyOption.ATOMIC_MOVE;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static java.nio.file.StandardOpenOption.WRITE;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

/** Verifies and atomically publishes managed snapshots without changing the browser API format. */
@Component
final class PublishedSnapshotStore {
    private static final int FORMAT = 1;
    static final int MAX_PAYLOAD_BYTES = 3 * 1024 * 1024;
    private static final int MAX_ARTIFACT_BYTES = 4 * 1024 * 1024 + 1024;
    private static final HexFormat HEX = HexFormat.of();
    private static final String HMAC = "HmacSHA256";
    private static final byte[] CONTEXT =
            ("threat-detection:reputation:" + FORMAT + ":" + ReputationIngestionSettings.SOURCE + "\n")
                    .getBytes(StandardCharsets.US_ASCII);

    private final JsonMapper json;
    private final Path destination;
    private final SecretKeySpec key;

    PublishedSnapshotStore(JsonMapper json, ReputationIngestionSettings settings,
                           @Value("${threat.reputation.snapshot-path:}") String path,
                           @Value("${threat.reputation.ingestion.signing-key:}") String signingKey) {
        this.json = json;
        if (!settings.enabled()) {
            destination = null;
            key = null;
            return;
        }
        if (path.isBlank() || !signingKey.matches("[0-9a-fA-F]{64}")) {
            throw new IllegalArgumentException("Managed reputation requires a snapshot path and a 32-byte hexadecimal signing key");
        }
        destination = Path.of(path).toAbsolutePath().normalize();
        if (destination.getParent() == null) {
            throw new IllegalArgumentException("Managed reputation requires a snapshot file path");
        }
        key = new SecretKeySpec(HEX.parseHex(signingKey), HMAC);
    }

    Published load() throws IOException {
        byte[] encoded;
        try (var input = Files.newInputStream(destination)) {
            encoded = input.readNBytes(MAX_ARTIFACT_BYTES + 1);
        }
        if (encoded.length > MAX_ARTIFACT_BYTES) throw invalidArtifact();
        try {
            Envelope envelope = json.readValue(encoded, Envelope.class);
            if (envelope == null || envelope.formatVersion() != FORMAT ||
                    !ReputationIngestionSettings.SOURCE.equals(envelope.source())) {
                throw invalidArtifact();
            }
            byte[] payload = Base64.getDecoder().decode(envelope.payload());
            if (payload.length > MAX_PAYLOAD_BYTES ||
                    !MessageDigest.isEqual(digest(payload), decodeHex(envelope.version())) ||
                    !MessageDigest.isEqual(authenticate(payload), decodeHex(envelope.hmacSha256()))) {
                throw invalidArtifact();
            }
            ReputationSnapshot snapshot = json.readValue(payload, ReputationSnapshot.class);
            validateManaged(snapshot);
            return new Published(envelope.version(), snapshot);
        } catch (RuntimeException failure) {
            throw invalidArtifact();
        }
    }

    Published publish(ReputationSnapshot snapshot) throws IOException {
        validateManaged(snapshot);
        if (!snapshot.isCurrent(Instant.now())) throw new IOException("Reputation source expired before publication");
        byte[] payload = json.writeValueAsBytes(snapshot);
        if (payload.length > MAX_PAYLOAD_BYTES) throw new IOException("Managed reputation payload exceeds the size limit");
        var envelope = new Envelope(FORMAT, ReputationIngestionSettings.SOURCE, HEX.formatHex(digest(payload)),
                Base64.getEncoder().encodeToString(payload), HEX.formatHex(authenticate(payload)));
        byte[] encoded = json.writeValueAsBytes(envelope);

        Path temporary = Files.createTempFile(destination.getParent(), ".reputation-", ".tmp");
        try {
            try (FileChannel file = FileChannel.open(temporary, WRITE)) {
                ByteBuffer buffer = ByteBuffer.wrap(encoded);
                while (buffer.hasRemaining()) file.write(buffer);
                file.force(true);
            }
            Files.move(temporary, destination, ATOMIC_MOVE, REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(temporary);
        }
        return new Published(envelope.version(), snapshot);
    }

    String version(ReputationSnapshot snapshot) throws IOException {
        return HEX.formatHex(digest(json.writeValueAsBytes(snapshot)));
    }

    boolean hasVersion(String version) {
        try {
            return version.equals(load().version());
        } catch (IOException | RuntimeException failure) {
            return false;
        }
    }

    private static void validateManaged(ReputationSnapshot snapshot) throws IOException {
        if (snapshot == null || snapshot.entries().isEmpty() ||
                snapshot.expiresAt().isAfter(snapshot.generatedAt().plus(ReputationIngestionSettings.MAX_AGE))) {
            throw invalidArtifact();
        }
    }

    private static byte[] decodeHex(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("Invalid digest");
        return HEX.parseHex(value);
    }

    private static byte[] digest(byte[] payload) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(payload);
        } catch (GeneralSecurityException failure) {
            throw new IllegalStateException("SHA-256 unavailable", failure);
        }
    }

    private byte[] authenticate(byte[] payload) {
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(key);
            mac.update(CONTEXT);
            return mac.doFinal(payload);
        } catch (GeneralSecurityException failure) {
            throw new IllegalStateException("Snapshot authentication unavailable", failure);
        }
    }

    private static IOException invalidArtifact() {
        return new IOException("Managed reputation artifact is invalid");
    }

    private record Envelope(int formatVersion, String source, String version, String payload, String hmacSha256) {}

    record Published(String version, ReputationSnapshot snapshot) {}
}
