package com.threatdetection.admin;

import javax.swing.*;
import java.awt.*;

/**
 * Main entry point for the Threat Detection Admin Swing application.
 * Creates a JFrame with a JTabbedPane containing all admin panels.
 */
public class AdminSwingApplication {

    public static void main(String[] args) {
        // Use system look and feel for native appearance
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            // Fall back to default
        }

        // Customize some UI defaults for a cleaner look
        UIManager.put("TabbedPane.selectedBackground", new Color(70, 130, 180));
        UIManager.put("TabbedPane.selectedForeground", Color.WHITE);
        UIManager.put("Table.alternateRowColor", new Color(245, 245, 250));

        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("🛡️ Threat Detection Admin Dashboard");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setSize(1200, 800);
            frame.setMinimumSize(new Dimension(900, 600));
            frame.setLocationRelativeTo(null);

            // Create the API client
            ApiClient apiClient = new ApiClient("http://localhost:8081");

            // Create tabbed pane
            JTabbedPane tabbedPane = new JTabbedPane();
            tabbedPane.setFont(new Font("Segoe UI", Font.PLAIN, 14));

            tabbedPane.addTab("📊 Dashboard", new DashboardPanel(apiClient));
            tabbedPane.addTab("📋 Threat Logs", new ThreatLogsPanel(apiClient));
            tabbedPane.addTab("🔔 Alerts", new AlertsPanel(apiClient));
            tabbedPane.addTab("📈 Session Summary", new SessionSummaryPanel(apiClient));
            tabbedPane.addTab("⏱️ Timeline", new TimelinePanel(apiClient));
            tabbedPane.addTab("🧪 Demo Simulator", new DemoSimulatorPanel(apiClient));

            frame.add(tabbedPane);
            frame.setVisible(true);
        });
    }
}
