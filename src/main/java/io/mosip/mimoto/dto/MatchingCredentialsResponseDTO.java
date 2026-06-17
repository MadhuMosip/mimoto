package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Set;

/**
 * Response DTO for the {@code GET /presentations/{pid}/credentials} endpoint.
 *
 * <p>The shape differs based on the spec version:
 * <ul>
 *   <li><b>Draft-23</b>: {@code availableCredentials} and {@code missingClaims} are populated;
 *       {@code queryGroups} is null.</li>
 *   <li><b>OVP 1.0 / DCQL</b>: {@code queryGroups} is populated; {@code availableCredentials}
 *       and {@code missingClaims} are null.</li>
 * </ul>
 *
 * Clients can use {@code isDcql} to decide which shape to render.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class MatchingCredentialsResponseDTO {

    // ── Draft-23 fields ────────────────────────────────────────────────────────

    @JsonProperty("availableCredentials")
    @Schema(description = "Flat list of credentials matching the presentation definition (Draft-23 only).")
    private List<CredentialDTO> availableCredentials;

    @JsonProperty("missingClaims")
    @Schema(description = "Claims required by the presentation definition but absent from all wallet credentials (Draft-23 only).")
    private Set<String> missingClaims;

    // ── OVP 1.0 / DCQL fields ─────────────────────────────────────────────────

    @JsonProperty("queryGroups")
    @Schema(description = "One group per DCQL credential query, each containing matched credentials and metadata (OVP 1.0 only).")
    private List<DcqlQueryGroup> queryGroups;

    // ── Common ────────────────────────────────────────────────────────────────

    @JsonProperty("isDcql")
    @Schema(description = "True when this response is for an OVP 1.0 / DCQL request. " +
            "Clients should use queryGroups when true and availableCredentials when false.")
    private boolean isDcql;
}
