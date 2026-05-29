package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MatchingCredentialsResponseDTO {

    @JsonProperty("specVersion")
    @Schema(description = "OpenID4VP spec version for this presentation session", example = "draft-23")
    private String specVersion;

    @JsonProperty("availableCredentials")
    @Schema(description = "List of credentials that match the presentation definition")
    private List<CredentialDTO> availableCredentials;

    @JsonProperty("credentialQueries")
    @Schema(description = "OVP v1: DCQL credential query matches grouped by query id")
    private List<CredentialQueryMatchDTO> credentialQueries;

    @JsonProperty("credentialSets")
    @Schema(description = "OVP v1: DCQL credential sets (options/required) describing valid combinations")
    private List<CredentialSetDTO> credentialSets;

    @JsonProperty("missingClaims")
    @Schema(description = "List of claims that are required but not available in any credential")
    private Set<String> missingClaims;
}
