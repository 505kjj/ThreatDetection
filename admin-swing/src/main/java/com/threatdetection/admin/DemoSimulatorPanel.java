package com.threatdetection.admin;

import com.fasterxml.jackson.databind.JsonNode;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Demo Simulator tab panel.
 * Generates simulated behavior requests and sends them to the backend.
 */
public class DemoSimulatorPanel extends JPanel {

    private final ApiClient apiClient;
    private final JTextArea resultArea;

    public DemoSimulatorPanel(ApiClient apiClient) {
        this.apiClient = apiClient;
        setLayout(new BorderLayout(10, 10));
        setBorder(new EmptyBorder(15, 15, 15, 15));

        // === Top: Buttons ===
        JPanel buttonPanel = new JPanel(new GridLayout(2, 2, 15, 15));
        buttonPanel.setBorder(new EmptyBorder(10, 50, 10, 50));

        JButton safeBtn = createSimButton("🟢 Simulate Safe User", new Color(46, 139, 87));
        safeBtn.addActionListener(e -> simulate("safe"));
        buttonPanel.add(safeBtn);

        JButton suspiciousBtn = createSimButton("🟡 Simulate Suspicious User", new Color(218, 165, 32));
        suspiciousBtn.addActionListener(e -> simulate("suspicious"));
        buttonPanel.add(suspiciousBtn);

        JButton highRiskBtn = createSimButton("🟠 Simulate High Risk User", new Color(255, 140, 0));
        highRiskBtn.addActionListener(e -> simulate("high_risk"));
        buttonPanel.add(highRiskBtn);

        JButton criticalBtn = createSimButton("🔴 Simulate Critical User", new Color(220, 20, 60));
        criticalBtn.addActionListener(e -> simulate("critical"));
        buttonPanel.add(criticalBtn);

        add(buttonPanel, BorderLayout.NORTH);

        // === Center: Result display ===
        resultArea = new JTextArea();
        resultArea.setFont(new Font("Consolas", Font.PLAIN, 13));
        resultArea.setEditable(false);
        resultArea.setLineWrap(true);
        resultArea.setWrapStyleWord(true);
        resultArea.setMargin(new Insets(15, 15, 15, 15));
        resultArea.setText("Click a simulation button to send a test request to the backend.\n\n" +
                "Each button generates appropriate behavior metadata and sends it to:\n" +
                "  POST /api/threat/analyze\n\n" +
                "The response (risk score, trust score, risk level, reasons, tags, action)\n" +
                "will be displayed here.");

        JScrollPane scrollPane = new JScrollPane(resultArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Simulation Result"));
        add(scrollPane, BorderLayout.CENTER);
    }

    private void simulate(String type) {
        Map<String, Object> request = buildRequest(type);
        resultArea.setText("Sending " + type + " simulation...\n");

        SwingWorker<JsonNode, Void> worker = new SwingWorker<>() {
            @Override
            protected JsonNode doInBackground() throws Exception {
                return apiClient.analyze(request);
            }

            @Override
            protected void done() {
                try {
                    JsonNode response = get();
                    StringBuilder sb = new StringBuilder();
                    sb.append("═══════════════════════════════════════\n");
                    sb.append("  SIMULATION RESULT: ").append(type.toUpperCase()).append("\n");
                    sb.append("═══════════════════════════════════════\n\n");

                    sb.append("  Risk Score:    ").append(response.path("riskScore").asInt(0)).append("\n");
                    sb.append("  Trust Score:   ").append(response.path("trustScore").asInt(0)).append("\n");
                    sb.append("  Risk Level:    ").append(response.path("riskLevel").asText("—")).append("\n");
                    sb.append("  Action:        ").append(response.path("action").asText("—")).append("\n");
                    sb.append("  Confidence:    ").append(response.path("confidence").asDouble(0)).append("\n\n");

                    sb.append("  Reasons:\n");
                    JsonNode reasons = response.path("reasons");
                    if (reasons.isArray()) {
                        for (JsonNode reason : reasons) {
                            sb.append("    • ").append(reason.asText()).append("\n");
                        }
                    }

                    sb.append("\n  Tags:\n");
                    JsonNode tags = response.path("tags");
                    if (tags.isArray()) {
                        for (JsonNode tag : tags) {
                            sb.append("    # ").append(tag.asText()).append("\n");
                        }
                    }

                    resultArea.setText(sb.toString());
                    resultArea.setCaretPosition(0);
                } catch (Exception e) {
                    resultArea.setText("Simulation failed: " + e.getMessage());
                }
            }
        };
        worker.execute();
    }

    private Map<String, Object> buildRequest(String type) {
        String sessionId = "SIM-" + UUID.randomUUID().toString().substring(0, 8);
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

        Map<String, Object> req = new LinkedHashMap<>();
        req.put("sessionId", sessionId);
        req.put("timestamp", timestamp);

        switch (type) {
            case "safe" -> {
                req.put("domain", "example.com");
                req.put("url", "https://example.com/home");
                req.put("path", "/home");
                req.put("referrer", "https://google.com");
                req.put("redirectCount", 0);
                req.put("eventType", "page_view");
                req.put("actionType", "navigation");
                req.put("pageCategory", "public");
                req.put("fieldType", "none");
                req.put("averageClickGapMs", 1200);
                req.put("clicksLast10Sec", 2);
                req.put("pagesVisitedLast30Sec", 1);
                req.put("tabSwitchCount", 0);
                req.put("copyPasteCount", 0);
                req.put("formSubmitCount", 0);
                req.put("failedActionCount", 0);
                req.put("deviceChanged", false);
            }
            case "suspicious" -> {
                req.put("domain", "demo.example.com");
                req.put("url", "https://demo.example.com/login");
                req.put("path", "/login");
                req.put("referrer", "");
                req.put("redirectCount", 1);
                req.put("eventType", "form_focus");
                req.put("actionType", "sensitive_action");
                req.put("pageCategory", "sensitive_page");
                req.put("fieldType", "email");
                req.put("averageClickGapMs", 400);
                req.put("clicksLast10Sec", 8);
                req.put("pagesVisitedLast30Sec", 3);
                req.put("tabSwitchCount", 2);
                req.put("copyPasteCount", 1);
                req.put("formSubmitCount", 1);
                req.put("failedActionCount", 0);
                req.put("deviceChanged", false);
            }
            case "high_risk" -> {
                req.put("domain", "demo.example.com");
                req.put("url", "https://demo.example.com/dashboard");
                req.put("path", "/dashboard");
                req.put("referrer", "https://suspicious-site.com");
                req.put("redirectCount", 2);
                req.put("eventType", "password_focus");
                req.put("actionType", "sensitive_action");
                req.put("pageCategory", "sensitive_page");
                req.put("fieldType", "password");
                req.put("averageClickGapMs", 200);
                req.put("clicksLast10Sec", 15);
                req.put("pagesVisitedLast30Sec", 6);
                req.put("tabSwitchCount", 4);
                req.put("copyPasteCount", 3);
                req.put("formSubmitCount", 3);
                req.put("failedActionCount", 2);
                req.put("deviceChanged", false);
            }
            case "critical" -> {
                req.put("domain", "demo.example.com");
                req.put("url", "https://demo.example.com/admin");
                req.put("path", "/admin");
                req.put("referrer", "");
                req.put("redirectCount", 3);
                req.put("eventType", "password_focus");
                req.put("actionType", "sensitive_action");
                req.put("pageCategory", "sensitive_page");
                req.put("fieldType", "password");
                req.put("averageClickGapMs", 100);
                req.put("clicksLast10Sec", 20);
                req.put("pagesVisitedLast30Sec", 10);
                req.put("tabSwitchCount", 8);
                req.put("copyPasteCount", 6);
                req.put("formSubmitCount", 5);
                req.put("failedActionCount", 4);
                req.put("deviceChanged", true);
            }
        }

        return req;
    }

    private JButton createSimButton(String text, Color color) {
        JButton btn = new JButton(text);
        btn.setFont(new Font("Segoe UI", Font.BOLD, 14));
        btn.setForeground(Color.WHITE);
        btn.setBackground(color);
        btn.setFocusPainted(false);
        btn.setBorderPainted(false);
        btn.setOpaque(true);
        btn.setPreferredSize(new Dimension(250, 50));
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        return btn;
    }
}
