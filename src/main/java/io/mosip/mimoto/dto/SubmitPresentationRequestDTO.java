package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.mosip.mimoto.dto.deserializer.SelectedCredentialsDeserializer;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * DTO for submitting a presentation with selected credentials or rejecting a verifier.
 *
 * The selectedCredentials field is polymorphic:
 *   - Array of strings  → Draft-23 path  e.g. ["vc-uuid-1", "vc-uuid-2"]
 *   - Array of objects  → DCQL path      e.g. [{ "queryId": "pid", "selectedCredentialIds": ["vc-uuid-1"] }]
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Request payload for submitting a presentation with selected credentials or rejecting a verifier")
public class SubmitPresentationRequestDTO {

    @Schema(
        description = "Selected credentials. " +
            "For Draft-23: array of credential ID strings. " +
            "For OVP 1.0 / DCQL: array of objects with queryId and selectedCredentialIds.",
        example = "[\"vc-uuid-111\"]  or  [{\"queryId\":\"pid_query\",\"selectedCredentialIds\":[\"vc-uuid-111\"]}]"
    )
    @JsonDeserialize(using = SelectedCredentialsDeserializer.class)
    private SelectedCredentials selectedCredentials;

    @Schema(
            description = "Selected SD-JWT claim paths per credential ID for selective disclosure (only for SD-JWT credentials).",
            example = "{\"cred-123\": [\"name\", \"dob\"]}")
    private Map<String, List<String>> selectedSdClaims;

    @Schema(
        description = "Error code for rejecting the verifier (used when user denies the presentation request)",
        example = "access_denied"
    )
    private String errorCode;

    @Schema(
        description = "Error message for rejecting the verifier (used when user denies the presentation request)",
        example = "User denied authorization to share credentials"
    )
    private String errorMessage;

    /**
     * Returns true when selectedCredentials is present and no error fields are set.
     */
    public boolean isSubmissionRequest() {
        boolean hasCredentials = selectedCredentials != null && !selectedCredentials.isEmpty();
        boolean hasErrorFields = (errorCode != null && !errorCode.trim().isEmpty()) ||
                                 (errorMessage != null && !errorMessage.trim().isEmpty());
        return hasCredentials && !hasErrorFields;
    }

    /** Returns true when this is a DCQL submission (selectedCredentials contains objects, not strings). */
    @JsonIgnore
    public boolean isDcqlSubmission() {
        return selectedCredentials != null && selectedCredentials.isDcql();
    }

    /**
     * Returns the credential IDs for Draft-23 submissions.
     */
    @JsonIgnore
    public List<String> getSelectedCredentialIds() {
        if (selectedCredentials == null) return null;
        return selectedCredentials.getCredentialIds();
    }

    /**
     * Returns the DCQL selections for OVP 1.0 submissions.
     */
    @JsonIgnore
    public List<DcqlCredentialSelection> getDcqlSelections() {
        if (selectedCredentials == null) return null;
        return selectedCredentials.getDcqlSelections();
    }

    /** Returns true when errorCode + errorMessage are present and no credentials are set. */
    public boolean isRejectionRequest() {
        boolean hasErrorFields = errorCode != null && !errorCode.trim().isEmpty() &&
                                errorMessage != null && !errorMessage.trim().isEmpty();
        boolean hasCredentials = selectedCredentials != null && !selectedCredentials.isEmpty();
        boolean hasSdClaims = selectedSdClaims != null && !selectedSdClaims.isEmpty();
        return hasErrorFields && !hasCredentials && !hasSdClaims;
    }
}
