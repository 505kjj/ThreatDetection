package com.example.threatdetection.reputation;

import java.io.IOException;
import java.time.Instant;

interface ThreatFeed {
    Result fetch(Instant now) throws IOException;

    record Result(ReputationSnapshot snapshot, int activeIndicators, int rejectedIndicators) {}
}
