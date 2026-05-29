package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SelectedCredentialMapping {

    @Schema(description = "Wallet credential identifier", example = "cred-123")
    private String credentialId;

    @Schema(description = "DCQL credential query identifier", example = "identity_verification")
    private String credentialQueryId;
}

