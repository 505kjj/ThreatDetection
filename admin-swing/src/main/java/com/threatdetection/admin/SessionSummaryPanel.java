package com.threatdetection.admin;

import com.fasterxml.jackson.databind.JsonNode;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.Iterator;
import java.util.Map;

/**
 * Session Summary tab panel.
 * Enter a session ID, load its aggregated summary from the backend.
 */
public class SessionSummaryPanel extends JPanel {

    private final ApiClient apiClient;
    private final JTextField sessionIdField;
    private final JTextArea summaryArea;

    public SessionSummaryPanel(ApiClient apiClient) {
        this.apiClient = apiClient;
        setLayout(new BorderLayout(10, 10));
        setBorder(new EmptyBorder(15, 15, 15, 15));

        // === Top: Input ===
        JPanel inputPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));

        inputPanel.add(new JLabel("Session ID:"));
        sessionIdField = new JTextField(25);
        sessionIdField.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        inputPanel.add(sessionIdField);

        JButton loadBtn = new JButton("📈 Load Summary");
        loadBtn.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        loadBtn.addActionListener(e -> loadSummary());
        inputPanel.add(loadBtn);

        add(inputPanel, BorderLayout.NORTH);

        // === Center: Summary display ===
        summaryArea = new JTextArea();
        summaryArea.setFont(new Font("Consolas", Font.PLAIN, 14));
        summaryArea.setEditable(false);
        summaryArea.setLineWrap(true);
        summaryArea.setWrapStyleWord(true);
        summaryArea.setMargin(new Insets(15, 15, 15, 15));
        summaryArea.setText("Enter a Session ID and click 'Load Summary' to view session risk profile.");

        JScrollPane scrollPane = new JScrollPane(summaryArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Session Summary"));
        add(scrollPane, BorderLayout.CENTER);
    }

    private void loadSummary() {
        String sessionId = sessionIdField.getText().trim();
        if (sessionId.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a Session ID.");
            return;
        }

        summaryArea.setText("Loading summary for session: " + sessionId + "...");

        SwingWorker<JsonNode, Void> worker = new SwingWorker<>() {
            @Override
            protected JsonNode doInBackground() throws Exception {
                return apiClient.getSessionSummary(sessionId);
            }

            @Override
            protected void done() {
                try {
                    JsonNode summary = get();
                    StringBuilder sb = new StringBuilder();
                    sb.append("═══════════════════════════════════════\n");
                    sb.append("  SESSION SUMMARY: ").append(sessionId).append("\n");
                    sb.append("═══════════════════════════════════════\n\n");

                    sb.append("  Highest Risk Score:  ").append(summary.path("highestRiskScore").asInt(0)).append("\n");
                    sb.append("  Trust Score:         ").append(summary.path("trustScore").asInt(0)).append("\n");
                    sb.append("  Highest Risk Level:  ").append(summary.path("highestRiskLevel").asText("—")).append("\n");
                    sb.append("  Total Events:        ").append(summary.path("totalEvents").asLong(0)).append("\n");
                    sb.append("  Total Warnings:      ").append(summary.path("totalWarnings").asLong(0)).append("\n");
                    sb.append("  Total High Risk:     ").append(summary.path("totalHighRisk").asLong(0)).append("\n");
                    sb.append("  Total Critical:      ").append(summary.path("totalCritical").asLong(0)).append("\n");
                    sb.append("  Final Action:        ").append(summary.path("finalAction").asText("—")).append("\n\n");

                    sb.append("  Main Reasons:\n");
                    JsonNode reasons = summary.path("mainReasons");
                    if (reasons.isArray()) {
                        for (JsonNode reason : reasons) {
                            sb.append("    • ").append(reason.asText()).append("\n");
                        }
                    } else {
                        sb.append("    • None\n");
                    }

                    if (summary.has("message")) {
                        sb.append("\n  ⚠ ").append(summary.path("message").asText()).append("\n");
                    }

                    summaryArea.setText(sb.toString());
                    summaryArea.setCaretPosition(0);
                } catch (Exception e) {
                    summaryArea.setText("Failed to load summary: " + e.getMessage());
                }
            }
        };
        worker.execute();
    }
}
