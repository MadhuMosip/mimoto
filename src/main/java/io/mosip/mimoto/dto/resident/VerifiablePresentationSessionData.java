package io.mosip.mimoto.dto.resident;

import io.mosip.mimoto.constant.SpecVersion;
import io.mosip.mimoto.dto.DecryptedCredentialDTO;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class VerifiablePresentationSessionData implements Serializable {

    private String presentationId;

    /** The original URL-encoded authorization request string from the verifier. */
    private String authorizationRequest;

    private Instant createdAt;

    private boolean isVerifierClientPreregistered;

    /**
     * Wallet credentials that matched the verifier's request.
     * Populated after {@code GET /credentials} and reused during submission.
     * Each entry carries a {@code descriptorId} identifying which query/descriptor it satisfies.
     */
    private List<DecryptedCredentialDTO> matchingCredentials;

    /**
     * The OpenID4VP specification version detected from the verifier's authorization request.
     * {@link SpecVersion#DRAFT_23} when the request contains {@code presentation_definition}.
     * {@link SpecVersion#V1_0} when the request contains {@code dcql_query}.
     * Defaults to {@link SpecVersion#DRAFT_23} when null (backward compatibility).
     */
    private SpecVersion specVersion;

    /** Returns true when this session is for an OVP 1.0 / DCQL verifier. */
    public boolean isDcql() {
        return SpecVersion.V1_0.equals(specVersion);
    }
}