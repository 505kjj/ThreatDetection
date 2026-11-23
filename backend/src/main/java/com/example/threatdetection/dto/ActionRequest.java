package com.example.threatdetection.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request to record an admin action taken on a session.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ActionRequest {

    @NotBlank
    @Pattern(regexp = ApiFields.SESSION_ID)
    private String sessionId;

    @NotBlank
    @Pattern(regexp = ApiFields.ACTION)
    private String action;
}
