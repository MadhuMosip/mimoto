package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.mosip.mimoto.constant.SpecVersion;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class VPResponseDTO {

    @Schema(description = "Unique identifier for the Verifiable Presentation session")
    String presentationId;

    @JsonProperty("verifier")
    @Schema(description = "Information about the Verifier who sent the Verifiable Presentation request")
    VerifiablePresentationVerifierDTO verifiablePresentationVerifierDTO;

    @JsonProperty("specVersion")
    @Schema(description = "OpenID4VP specification version detected from the verifier's authorization request. " +
            "DRAFT_23 = presentation_definition flow. V1_0 = DCQL flow.")
    SpecVersion specVersion;
}
