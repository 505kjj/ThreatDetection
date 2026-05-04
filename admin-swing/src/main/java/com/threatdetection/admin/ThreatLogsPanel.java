package com.threatdetection.admin;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.List;
import java.util.Map;

/**
 * Threat Logs tab panel with JTable, filtering, and detail view.
 */
public class ThreatLogsPanel extends JPanel {

    private final ApiClient apiClient;
    private final DefaultTableModel tableModel;
    private final JTable table;
    private final JTextArea detailsArea;
    private final JComboBox<String> riskFilter;
    private final JTextField searchField;

    private List<Map<String, Object>> currentLogs;

    private static final String[] COLUMNS = {
            "Session ID", "Domain", "Risk Score", "Trust Score", "Risk Level", "Action", "Timestamp"
    };

    public ThreatLogsPanel(ApiClient apiClient) {
        this.apiClient = apiClient;
        setLayout(new BorderLayout(10, 10));
        setBorder(new EmptyBorder(10, 10, 10, 10));

        // === Top: Filter bar ===
        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));

        filterPanel.add(new JLabel("Risk Level:"));
        riskFilter = new JComboBox<>(new String[]{"All", "Safe", "Suspicious", "High Risk", "Critical"});
        riskFilter.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        filterPanel.add(riskFilter);

        filterPanel.add(new JLabel("Search:"));
        searchField = new JTextField(20);
        searchField.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        filterPanel.add(searchField);

        JButton refreshBtn = new JButton("🔄 Refresh");
        refreshBtn.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        refreshBtn.addActionListener(e -> loadLogs());
        filterPanel.add(refreshBtn);

        JButton detailsBtn = new JButton("📋 View Details");
        detailsBtn.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        detailsBtn.addActionListener(e -> showDetails());
        filterPanel.add(detailsBtn);

        add(filterPanel, BorderLayout.NORTH);

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
        table.setAutoCreateRowSorter(true);

        JScrollPane scrollPane = new JScrollPane(table);
        add(scrollPane, BorderLayout.CENTER);

        // === Bottom: Details area ===
        detailsArea = new JTextArea(6, 80);
        detailsArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        detailsArea.setEditable(false);
        detailsArea.setLineWrap(true);
        detailsArea.setWrapStyleWord(true);
        detailsArea.setBorder(BorderFactory.createTitledBorder("Event Details"));

        JScrollPane detailsScroll = new JScrollPane(detailsArea);
        add(detailsScroll, BorderLayout.SOUTH);

        // Auto-load
        loadLogs();
    }

    private void loadLogs() {
        SwingWorker<List<Map<String, Object>>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<Map<String, Object>> doInBackground() throws Exception {
                String level = (String) riskFilter.getSelectedItem();
                String search = searchField.getText().trim();
                return apiClient.getFilteredLogs(level, null, search);
            }

            @Override
            protected void done() {
                try {
                    currentLogs = get();
                    tableModel.setRowCount(0);
                    for (Map<String, Object> log : currentLogs) {
                        tableModel.addRow(new Object[]{
                                str(log, "sessionId"),
                                str(log, "domain"),
                                log.getOrDefault("riskScore", 0),
                                log.getOrDefault("trustScore", 0),
                                str(log, "riskLevel"),
                                str(log, "action"),
                                str(log, "createdAt")
                        });
                    }
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(ThreatLogsPanel.this,
                            "Failed to load logs: " + e.getMessage(),
                            "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        worker.execute();
    }

    private void showDetails() {
        int row = table.getSelectedRow();
        if (row < 0 || currentLogs == null || row >= currentLogs.size()) {
            detailsArea.setText("Select a row first.");
            return;
        }

        int modelRow = table.convertRowIndexToModel(row);
        Map<String, Object> log = currentLogs.get(modelRow);

        StringBuilder sb = new StringBuilder();
        sb.append("Session ID:    ").append(str(log, "sessionId")).append("\n");
        sb.append("Domain:        ").append(str(log, "domain")).append("\n");
        sb.append("URL:           ").append(str(log, "url")).append("\n");
        sb.append("Risk Score:    ").append(log.getOrDefault("riskScore", 0)).append("\n");
        sb.append("Trust Score:   ").append(log.getOrDefault("trustScore", 0)).append("\n");
        sb.append("Risk Level:    ").append(str(log, "riskLevel")).append("\n");
        sb.append("Event Type:    ").append(str(log, "eventType")).append("\n");
        sb.append("Action Type:   ").append(str(log, "actionType")).append("\n");
        sb.append("Page Category: ").append(str(log, "pageCategory")).append("\n");
        sb.append("Field Type:    ").append(str(log, "fieldType")).append("\n");
        sb.append("Reasons:       ").append(str(log, "reasons")).append("\n");
        sb.append("Tags:          ").append(str(log, "tags")).append("\n");
        sb.append("Action:        ").append(str(log, "action")).append("\n");
        sb.append("Timestamp:     ").append(str(log, "createdAt")).append("\n");

        detailsArea.setText(sb.toString());
        detailsArea.setCaretPosition(0);
    }

    private String str(Map<String, Object> map, String key) {
        Object val = map.get(key);
        return val != null ? val.toString() : "—";
    }
}
