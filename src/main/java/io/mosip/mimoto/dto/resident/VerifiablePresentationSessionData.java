package io.mosip.mimoto.dto.resident;

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
    private String authorizationRequest;
    /**
     * OpenID4VP spec version associated with this presentation session.
     * Expected values: "draft-23" | "v1"
     */
    private String specVersion;
    private Instant createdAt;
    private boolean isVerifierClientPreregistered;
    private List<DecryptedCredentialDTO> matchingCredentials;
}