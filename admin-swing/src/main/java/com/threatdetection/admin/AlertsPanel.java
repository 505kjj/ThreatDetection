package com.threatdetection.admin;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.List;
import java.util.Map;

/**
 * Alerts tab panel showing all alerts with resolve functionality.
 */
public class AlertsPanel extends JPanel {

    private final ApiClient apiClient;
    private final DefaultTableModel tableModel;
    private final JTable table;

    private List<Map<String, Object>> currentAlerts;

    private static final String[] COLUMNS = {
            "Alert ID", "Session ID", "Domain", "Risk Score", "Risk Level",
            "Message", "Resolved", "Created At"
    };

    public AlertsPanel(ApiClient apiClient) {
        this.apiClient = apiClient;
        setLayout(new BorderLayout(10, 10));
        setBorder(new EmptyBorder(10, 10, 10, 10));

        // === Top bar ===
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));

        JButton refreshBtn = new JButton("🔄 Refresh Alerts");
        refreshBtn.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        refreshBtn.addActionListener(e -> loadAlerts());
        topPanel.add(refreshBtn);

        JButton resolveBtn = new JButton("✅ Resolve Selected Alert");
        resolveBtn.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        resolveBtn.addActionListener(e -> resolveSelected());
        topPanel.add(resolveBtn);

        add(topPanel, BorderLayout.NORTH);

        // === Table ===
        tableModel = new DefaultTableModel(COLUMNS, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        table = new JTable(tableModel);
        table.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        table.setRowHeight(28);
        table.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 12));
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);

        // Set column widths
        table.getColumnModel().getColumn(5).setPreferredWidth(300); // Message

        JScrollPane scrollPane = new JScrollPane(table);
        add(scrollPane, BorderLayout.CENTER);

        // Auto-load
        loadAlerts();
    }

    private void loadAlerts() {
        SwingWorker<List<Map<String, Object>>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<Map<String, Object>> doInBackground() throws Exception {
                return apiClient.getAlerts();
            }

            @Override
            protected void done() {
                try {
                    currentAlerts = get();
                    tableModel.setRowCount(0);
                    for (Map<String, Object> alert : currentAlerts) {
                        tableModel.addRow(new Object[]{
                                alert.getOrDefault("id", "—"),
                                str(alert, "sessionId"),
                                str(alert, "domain"),
                                alert.getOrDefault("riskScore", 0),
                                str(alert, "riskLevel"),
                                str(alert, "message"),
                                alert.getOrDefault("resolved", false),
                                str(alert, "createdAt")
                        });
                    }
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(AlertsPanel.this,
                            "Failed to load alerts: " + e.getMessage(),
                            "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        worker.execute();
    }

    private void resolveSelected() {
        int row = table.getSelectedRow();
        if (row < 0 || currentAlerts == null || row >= currentAlerts.size()) {
            JOptionPane.showMessageDialog(this, "Select an alert to resolve.");
            return;
        }

        int modelRow = table.convertRowIndexToModel(row);
        Map<String, Object> alert = currentAlerts.get(modelRow);
        Object idObj = alert.get("id");
        if (idObj == null) return;

        long alertId = Long.parseLong(idObj.toString());

        SwingWorker<Void, Void> worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() throws Exception {
                apiClient.resolveAlert(alertId);
                return null;
            }

            @Override
            protected void done() {
                try {
                    get();
                    JOptionPane.showMessageDialog(AlertsPanel.this,
                            "Alert #" + alertId + " resolved successfully.");
                    loadAlerts();
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(AlertsPanel.this,
                            "Failed to resolve alert: " + e.getMessage(),
                            "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        worker.execute();
    }

    private String str(Map<String, Object> map, String key) {
        Object val = map.get(key);
        return val != null ? val.toString() : "—";
    }
}
