package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CredentialSetDTO {

    @JsonProperty("required")
    @Schema(description = "Whether at least one option must be satisfied", example = "true")
    private boolean required;

    @JsonProperty("options")
    @Schema(description = "OR options; each option is an AND group of query IDs")
    private List<CredentialSetOptionDTO> options;
}

