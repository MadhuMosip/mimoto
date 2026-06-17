package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Carries the user's credential selection for one DCQL credential query (OVP 1.0).
 *
 * <p>Included in {@link SubmitPresentationRequestDTO#getDcqlSelections()} when the
 * presentation flow is OVP 1.0. Each entry maps one {@code queryId} — matching
 * {@code dcql_query.credentials[i].id} — to the credential(s) the user selected
 * for that query.
 *
 * <p>Example JSON:
 * <pre>
 * { "queryId": "pid_query", "selectedCredentialIds": ["vc-uuid-1"] }
 * </pre>
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DcqlCredentialSelection {

    @JsonProperty("queryId")
    @Schema(description = "The credential query id from dcql_query.credentials[i].id",
            example = "pid_query")
    private String queryId;

    @JsonProperty("selectedCredentialIds")
    @Schema(description = "One or more wallet credential IDs the user selected for this query",
            example = "[\"vc-uuid-1\"]")
    private List<String> selectedCredentialIds;
}
