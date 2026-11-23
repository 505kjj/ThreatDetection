package com.example.threatdetection.reputation;

import java.util.Optional;

/** Supplies publishable threat indicators without receiving browsing destinations. */
public interface ReputationProvider {
    Optional<ReputationSnapshot> current();
}
