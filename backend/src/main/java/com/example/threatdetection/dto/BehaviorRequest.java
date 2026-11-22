package com.example.threatdetection.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

/**
 * Behavior metadata sent from the Chrome extension.
 * Contains ONLY metadata — never actual form values, passwords, or sensitive data.
 */
@Getter
@Setter
public class BehaviorRequest {

    @NotBlank
    @Pattern(regexp = ApiFields.SESSION_ID)
    private String sessionId;

    @Min(0)
    @Max(100)
    private int redirectCount;

    @NotBlank
    @Pattern(regexp = ApiFields.EVENT)
    private String eventType;

    @NotBlank
    @Pattern(regexp = ApiFields.ACTION_TYPE)
    private String actionType = "normal_action";

    @NotBlank
    @Pattern(regexp = ApiFields.PAGE_CATEGORY)
    private String pageCategory = "normal_page";

    @Min(-1)
    @Max(10_000)
    private int averageClickGapMs = -1;

    @Min(0)
    @Max(1000)
    private int clicksLast10Sec;

    @Min(0)
    @Max(1000)
    private int pagesVisitedLast30Sec;

    @Min(0)
    @Max(1000)
    private int tabSwitchCount;

    @Min(0)
    @Max(1000)
    private int copyPasteCount;

    @Min(0)
    @Max(1000)
    private int formSubmitCount;

    @Min(0)
    @Max(1000)
    private int failedActionCount;

    private boolean deviceChanged;
}
