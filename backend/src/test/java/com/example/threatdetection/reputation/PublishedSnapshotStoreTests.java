package com.example.threatdetection.reputation;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

class PublishedSnapshotStoreTests {
    @TempDir Path directory;
    private final JsonMapper json = JsonMapper.builder().build();
    private final ReputationIngestionSettings settings = new ReputationIngestionSettings(true, false, "PT5M");

    @Test
    void publishesAndRejectsTamperingEvenIfTheChecksumIsRecomputed() throws Exception {
        Path path = directory.resolve("current.json");
        var store = new PublishedSnapshotStore(json, settings, path.toString(), key());
        Instant now = Instant.now();
        var snapshot = testSnapshot("original.example.test", now.minusSeconds(5), now.plusSeconds(60));
        var publication = store.publish(snapshot);
        assertThat(store.load()).isEqualTo(publication);
        assertThat(store.version(snapshot)).isEqualTo(publication.version());
        var artifact = (ObjectNode) json.readTree(Files.readAllBytes(path));
        assertThat(artifact.path("formatVersion").asInt()).isEqualTo(1);

        byte[] modified = json.writeValueAsBytes(testSnapshot("modified.example.test", snapshot.generatedAt(),
                snapshot.expiresAt()));
        artifact.put("payload", Base64.getEncoder().encodeToString(modified));
        artifact.put("version", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(modified)));
        Files.write(path, json.writeValueAsBytes(artifact));
        assertThatThrownBy(store::load).isInstanceOf(IOException.class);
    }

    @Test
    void rejectsWrongKeyAndPreservesCurrentFileOnPrepublicationFailure() throws Exception {
        Path path = directory.resolve("current.json");
        var store = new PublishedSnapshotStore(json, settings, path.toString(), key());
        Instant now = Instant.now();
        store.publish(testSnapshot("original.example.test", now.minusSeconds(2), now.plusSeconds(60)));
        byte[] before = Files.readAllBytes(path);
        var otherReader = new PublishedSnapshotStore(json, settings, path.toString(), key());
        assertThatThrownBy(otherReader::load).isInstanceOf(IOException.class);
        assertThatThrownBy(() -> store.publish(testSnapshot("too-old.example.test",
                now.minusSeconds(901), now.minusSeconds(1)))).isInstanceOf(IOException.class);
        assertThatThrownBy(() -> store.publish(testSnapshot("too-long.example.test",
                now, now.plusSeconds(901)))).isInstanceOf(IOException.class);
        assertThat(Files.readAllBytes(path)).isEqualTo(before);
    }

    @Test
    void retainsLastVerifiedSnapshotOnCorruptionAndEnforcesOriginalExpiry() throws Exception {
        Path path = directory.resolve("current.json");
        var store = new PublishedSnapshotStore(json, settings, path.toString(), key());
        Instant now = Instant.now();
        var snapshot = testSnapshot("last-good.example.test", now.minusSeconds(5), now.plusSeconds(3));
        store.publish(snapshot);
        var provider = new FileReputationProvider(json, path.toString(), settings, store);
        provider.refresh();
        Files.writeString(path, "{\"broken\":true}");
        provider.refresh();
        assertThat(provider.current()).contains(snapshot);
        await().atMost(Duration.ofSeconds(7)).until(() -> provider.current().isEmpty());
        assertThat(provider.loadedPublication()).isPresent();
    }

    @Test
    void rejectsAValidlySignedButOlderPublicationDuringReload() throws Exception {
        Path path = directory.resolve("current.json");
        var store = new PublishedSnapshotStore(json, settings, path.toString(), key());
        Instant now = Instant.now();
        var newer = testSnapshot("new.example.test", now.minusSeconds(1), now.plusSeconds(60));
        store.publish(newer);
        var provider = new FileReputationProvider(json, path.toString(), settings, store);
        provider.refresh();
        store.publish(testSnapshot("old.example.test", now.minusSeconds(60), now.plusSeconds(60)));
        provider.refresh();
        assertThat(provider.current()).contains(newer);
    }

    private static ReputationSnapshot testSnapshot(String host, Instant from, Instant to) {
        return new ReputationSnapshot(from, to, List.of(new ReputationSnapshot.Entry(
                ReputationSnapshot.Kind.HOST, host, ReputationSnapshot.Threat.PHISHING)));
    }

    static String key() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }
}
