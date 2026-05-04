package com.example.threatdetection.rules;

import com.example.threatdetection.dto.BehaviorRequest;
import com.example.threatdetection.dto.RiskSignal;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates risk from device or browser fingerprint changes within a session.
 * A changed device mid-session indicates session hijacking.
 */
@Component
public class DeviceOrBrowserChangeRiskRule implements RiskRule {

    @Override
    public String getRuleName() {
        return "DeviceOrBrowserChangeRiskRule";
    }

    @Override
    public List<RiskSignal> evaluate(BehaviorRequest request) {
        List<RiskSignal> signals = new ArrayList<>();

        if (request.isDeviceChanged()) {
            signals.add(RiskSignal.builder()
                    .score(20)
                    .reason("Device or browser fingerprint changed during active session (possible session hijacking)")
                    .tag("device_change")
                    .category("session")
                    .build());
        }

        return signals;
    }
}
