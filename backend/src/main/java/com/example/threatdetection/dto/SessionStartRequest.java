package com.example.threatdetection.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request to start or register a new threat monitoring session.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SessionStartRequest {

    @NotBlank
    @Pattern(regexp = ApiFields.HOST)
    private String domain;
}
