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
public class CredentialQueryMatchDTO {

    @JsonProperty("id")
    @Schema(description = "DCQL credential query identifier", example = "identity_verification")
    private String id;

    @JsonProperty("allowMultipleCredentials")
    @Schema(description = "Whether the verifier allows multiple credentials for this query", example = "false")
    private boolean allowMultipleCredentials;

    @JsonProperty("matchingCredentials")
    @Schema(description = "Credentials in the wallet that match this query")
    private List<CredentialDTO> matchingCredentials;

    @JsonProperty("missingClaims")
    @Schema(description = "Requested claims that could not be satisfied for this query")
    private List<String> missingClaims;

    @JsonProperty("failureReason")
    @Schema(description = "High-level failure reason for this query (if any)")
    private String failureReason;
}

