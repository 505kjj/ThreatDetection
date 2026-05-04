package com.threatdetection.admin;

import com.fasterxml.jackson.databind.JsonNode;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;

/**
 * Dashboard tab panel showing overall system statistics and health.
 */
public class DashboardPanel extends JPanel {

    private final ApiClient apiClient;

    private final JLabel totalLogsLabel = createValueLabel("—");
    private final JLabel safeCountLabel = createValueLabel("—");
    private final JLabel suspiciousCountLabel = createValueLabel("—");
    private final JLabel highRiskCountLabel = createValueLabel("—");
    private final JLabel criticalCountLabel = createValueLabel("—");
    private final JLabel latestAlertLabel = createValueLabel("—");
    private final JLabel healthStatusLabel = createValueLabel("—");

    public DashboardPanel(ApiClient apiClient) {
        this.apiClient = apiClient;
        setLayout(new BorderLayout(10, 10));
        setBorder(new EmptyBorder(20, 20, 20, 20));

        // Header
        JLabel header = new JLabel("System Dashboard", SwingConstants.CENTER);
        header.setFont(new Font("Segoe UI", Font.BOLD, 24));
        header.setBorder(new EmptyBorder(0, 0, 15, 0));
        add(header, BorderLayout.NORTH);

        // Stats grid
        JPanel statsPanel = new JPanel(new GridLayout(2, 4, 15, 15));
        statsPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        statsPanel.add(createStatCard("Total Logs", totalLogsLabel, new Color(70, 130, 180)));
        statsPanel.add(createStatCard("Safe", safeCountLabel, new Color(46, 139, 87)));
        statsPanel.add(createStatCard("Suspicious", suspiciousCountLabel, new Color(218, 165, 32)));
        statsPanel.add(createStatCard("High Risk", highRiskCountLabel, new Color(255, 140, 0)));
        statsPanel.add(createStatCard("Critical", criticalCountLabel, new Color(220, 20, 60)));
        statsPanel.add(createStatCard("Latest Alert", latestAlertLabel, new Color(148, 103, 189)));
        statsPanel.add(createStatCard("Backend Health", healthStatusLabel, new Color(60, 179, 113)));

        // Refresh button
        JPanel refreshPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        JButton refreshBtn = new JButton("🔄 Refresh Dashboard");
        refreshBtn.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        refreshBtn.setPreferredSize(new Dimension(200, 40));
        refreshBtn.addActionListener(e -> refreshDashboard());
        refreshPanel.add(refreshBtn);

        // Backend URL config
        JPanel configPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        configPanel.add(new JLabel("Backend URL:"));
        JTextField urlField = new JTextField(apiClient.getBaseUrl(), 30);
        urlField.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        configPanel.add(urlField);
        JButton updateUrlBtn = new JButton("Update");
        updateUrlBtn.addActionListener(e -> {
            apiClient.setBaseUrl(urlField.getText().trim());
            refreshDashboard();
        });
        configPanel.add(updateUrlBtn);

        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(refreshPanel, BorderLayout.NORTH);
        bottomPanel.add(configPanel, BorderLayout.SOUTH);

        add(statsPanel, BorderLayout.CENTER);
        add(bottomPanel, BorderLayout.SOUTH);

        // Auto-refresh on load
        refreshDashboard();
    }

    private void refreshDashboard() {
        SwingWorker<Void, Void> worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                try {
                    // Health check
                    JsonNode health = apiClient.getHealth();
                    SwingUtilities.invokeLater(() ->
                            healthStatusLabel.setText(health.path("status").asText("UNKNOWN")));
                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> healthStatusLabel.setText("❌ OFFLINE"));
                }

                try {
                    // Dashboard stats
                    JsonNode stats = apiClient.getDashboardStats();
                    SwingUtilities.invokeLater(() -> {
                        totalLogsLabel.setText(String.valueOf(stats.path("totalLogs").asLong(0)));
                        safeCountLabel.setText(String.valueOf(stats.path("safeCount").asLong(0)));
                        suspiciousCountLabel.setText(String.valueOf(stats.path("suspiciousCount").asLong(0)));
                        highRiskCountLabel.setText(String.valueOf(stats.path("highRiskCount").asLong(0)));
                        criticalCountLabel.setText(String.valueOf(stats.path("criticalCount").asLong(0)));
                    });
                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> totalLogsLabel.setText("Error"));
                }

                try {
                    // Latest alert
                    JsonNode alert = apiClient.getLatestAlert();
                    String alertText = alert.has("message")
                            ? alert.path("riskLevel").asText() + " - " + alert.path("domain").asText()
                            : "No alerts";
                    SwingUtilities.invokeLater(() -> latestAlertLabel.setText(alertText));
                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> latestAlertLabel.setText("—"));
                }

                return null;
            }
        };
        worker.execute();
    }

    private JPanel createStatCard(String title, JLabel valueLabel, Color color) {
        JPanel card = new JPanel(new BorderLayout(5, 5));
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(color, 2),
                new EmptyBorder(15, 15, 15, 15)
        ));
        card.setBackground(Color.WHITE);

        JLabel titleLabel = new JLabel(title, SwingConstants.CENTER);
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 13));
        titleLabel.setForeground(color);

        valueLabel.setHorizontalAlignment(SwingConstants.CENTER);
        valueLabel.setForeground(color.darker());

        card.add(titleLabel, BorderLayout.NORTH);
        card.add(valueLabel, BorderLayout.CENTER);

        return card;
    }

    private static JLabel createValueLabel(String text) {
        JLabel label = new JLabel(text, SwingConstants.CENTER);
        label.setFont(new Font("Segoe UI", Font.BOLD, 28));
        return label;
    }
}
