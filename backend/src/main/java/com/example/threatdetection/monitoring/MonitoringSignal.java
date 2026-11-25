package com.example.threatdetection.monitoring;

public enum MonitoringSignal {
    PHISHING(Category.PHISHING, Source.REPUTATION, "The active reputation snapshot matched an indicator classified as phishing."),
    MALWARE(Category.MALWARE, Source.REPUTATION, "The active reputation snapshot matched an indicator classified as malware."),
    EMBEDDED_OFFICIAL_DOMAIN(Category.FINANCIAL_IMPERSONATION, Source.FINANCIAL_RULES,
            "A verified financial address appeared inside a hostname controlled by another domain."),
    REGISTERED_BRAND(Category.FINANCIAL_IMPERSONATION, Source.FINANCIAL_RULES,
            "The registered domain used a financial brand name outside its verified domains."),
    REGISTERED_TYPO(Category.FINANCIAL_IMPERSONATION, Source.FINANCIAL_RULES,
            "The registered domain resembled a financial brand name with one typing change."),
    REGISTERED_HOMOGRAPH(Category.FINANCIAL_IMPERSONATION, Source.FINANCIAL_RULES,
            "The registered domain used Unicode characters resembling a financial brand name."),
    SUBDOMAIN_BRAND(Category.FINANCIAL_IMPERSONATION, Source.FINANCIAL_RULES,
            "A subdomain used a financial brand name under a different registered domain."),
    SUBDOMAIN_TYPO(Category.FINANCIAL_IMPERSONATION, Source.FINANCIAL_RULES,
            "A subdomain combined a financial term with a one-character variant of a financial brand."),
    SUBDOMAIN_HOMOGRAPH(Category.FINANCIAL_IMPERSONATION, Source.FINANCIAL_RULES,
            "A subdomain used Unicode characters resembling a financial brand name."),
    FINANCIAL_PASSWORD_FORM(Category.FINANCIAL_IMPERSONATION, Source.FINANCIAL_RULES,
            "The browser observed a visible password field on an unverified financial lookalike."),
    FINANCIAL_PAYMENT_FORM(Category.FINANCIAL_IMPERSONATION, Source.FINANCIAL_RULES,
            "The browser observed visible card-detail fields on an unverified financial lookalike."),
    FINANCIAL_EXTERNAL_FORM(Category.FINANCIAL_IMPERSONATION, Source.FINANCIAL_RULES,
            "The browser observed a credential form with a declared action on an unrelated origin."),
    SUSPICIOUS_BEHAVIOR(Category.SUSPICIOUS_BEHAVIOR, Source.BEHAVIOR_RULES,
            "The activity analysis returned a suspicious-behavior advisory.");

    final Category category;
    final Source source;
    final String reason;

    MonitoringSignal(Category category, Source source, String reason) {
        this.category = category;
        this.source = source;
        this.reason = reason;
    }

    Severity severity() {
        return source == Source.REPUTATION ? Severity.HIGH : Severity.CAUTION;
    }

    boolean permits(Action action) {
        return switch (action) {
            case WARNED -> true;
            case BLOCKED -> source == Source.REPUTATION;
            case BYPASSED -> this == PHISHING;
        };
    }

    enum Category { PHISHING, MALWARE, FINANCIAL_IMPERSONATION, SUSPICIOUS_BEHAVIOR }
    enum Source { REPUTATION, FINANCIAL_RULES, BEHAVIOR_RULES }
    enum Severity { HIGH, CAUTION }
    public enum Action { BLOCKED, WARNED, BYPASSED }
}
