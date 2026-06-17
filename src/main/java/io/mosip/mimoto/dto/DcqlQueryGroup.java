package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Set;

/**
 * Represents the matching result for a single DCQL credential query (OVP 1.0).
 *
 * <p>One {@code DcqlQueryGroup} is returned per entry in {@code dcql_query.credentials}.
 * The UI uses these groups to render separate credential-selection sections — one
 * per query — instead of a single flat list as used in Draft-23.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DcqlQueryGroup {

    @JsonProperty("queryId")
    @Schema(description = "The credential query id from the DCQL query (dcql_query.credentials[i].id)")
    private String queryId;

    @JsonProperty("required")
    @Schema(description = "Whether the wallet MUST satisfy this query. Derived from credential_sets.required.")
    private boolean required;

    @JsonProperty("multiple")
    @Schema(description = "Whether the verifier accepts more than one credential for this query.")
    private boolean multiple;

    @JsonProperty("availableCredentials")
    @Schema(description = "Wallet credentials that match this credential query.")
    private List<CredentialDTO> availableCredentials;

    @JsonProperty("missingClaims")
    @Schema(description = "Claim paths requested by the query that could not be found in any wallet credential.")
    private Set<String> missingClaims;
}
