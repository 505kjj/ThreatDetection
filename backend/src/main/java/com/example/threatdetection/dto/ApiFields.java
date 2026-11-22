package com.example.threatdetection.dto;

public final class ApiFields {

    public static final String SESSION_ID = "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
    public static final String HOST = "(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
            + "(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*";
    public static final String HOST_FILTER = "[a-zA-Z0-9.-]{0,253}";
    public static final String LOG_SEARCH = "[a-zA-Z0-9. _-]{0,100}";
    public static final String RISK_LEVEL = "Safe|Suspicious|High Risk|Critical";
    public static final String ACTION = "ALLOW|SHOW_WARNING|FORCE_RELOGIN|ADMIN_ALERT";
    public static final String EVENT = "page_view|sensitive_page_visit|navigation_change|password_focus|form_focus"
            + "|form_submit|copy_paste|rapid_clicking|tab_blur|tab_focus|heartbeat|recheck_risk";
    public static final String ACTION_TYPE = "normal_action|navigation|sensitive_action|behavior_anomaly|session_anomaly";
    public static final String PAGE_CATEGORY = "normal_page|sensitive_page";

    private ApiFields() {}
}
