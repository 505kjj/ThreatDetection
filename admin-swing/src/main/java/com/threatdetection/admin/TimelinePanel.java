package com.threatdetection.admin;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.List;
import java.util.Map;

/**
 * Timeline tab panel.
 * Shows chronological risk logs for a given session.
 */
public class TimelinePanel extends JPanel {

    private final ApiClient apiClient;
    private final JTextField sessionIdField;
    private final DefaultTableModel tableModel;
    private final JTable table;

    private static final String[] COLUMNS = {
            "Timestamp", "Event Type", "Risk Score", "Trust Score", "Risk Level", "Action", "Reasons"
    };

    public TimelinePanel(ApiClient apiClient) {
        this.apiClient = apiClient;
        setLayout(new BorderLayout(10, 10));
        setBorder(new EmptyBorder(10, 10, 10, 10));

        // === Top: Input ===
        JPanel inputPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));

        inputPanel.add(new JLabel("Session ID:"));
        sessionIdField = new JTextField(25);
        sessionIdField.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        inputPanel.add(sessionIdField);

        JButton loadBtn = new JButton("⏱️ Load Timeline");
        loadBtn.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        loadBtn.addActionListener(e -> loadTimeline());
        inputPanel.add(loadBtn);

        add(inputPanel, BorderLayout.NORTH);

        // === Center: Table ===
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

        // Wider reasons column
        table.getColumnModel().getColumn(6).setPreferredWidth(300);

        JScrollPane scrollPane = new JScrollPane(table);
        add(scrollPane, BorderLayout.CENTER);
    }

    private void loadTimeline() {
        String sessionId = sessionIdField.getText().trim();
        if (sessionId.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a Session ID.");
            return;
        }

        SwingWorker<List<Map<String, Object>>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<Map<String, Object>> doInBackground() throws Exception {
                return apiClient.getTimeline(sessionId);
            }

            @Override
            protected void done() {
                try {
                    List<Map<String, Object>> timeline = get();
                    tableModel.setRowCount(0);

                    if (timeline.isEmpty()) {
                        JOptionPane.showMessageDialog(TimelinePanel.this,
                                "No timeline data found for session: " + sessionId);
                        return;
                    }

                    for (Map<String, Object> entry : timeline) {
                        tableModel.addRow(new Object[]{
                                str(entry, "createdAt"),
                                str(entry, "eventType"),
                                entry.getOrDefault("riskScore", 0),
                                entry.getOrDefault("trustScore", 0),
                                str(entry, "riskLevel"),
                                str(entry, "action"),
                                str(entry, "reasons")
                        });
                    }
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(TimelinePanel.this,
                            "Failed to load timeline: " + e.getMessage(),
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
