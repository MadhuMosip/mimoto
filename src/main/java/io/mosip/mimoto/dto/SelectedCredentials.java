package io.mosip.mimoto.dto;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import io.mosip.mimoto.dto.serializer.SelectedCredentialsSerializer;
import lombok.Getter;

import java.util.List;

/**
 * Wrapper that holds the selectedCredentials payload in either of its two forms:
 *   - Draft-23: a list of plain credential ID strings
 *   - DCQL:     a list of DcqlCredentialSelection objects (queryId + selectedCredentialIds)
 *
 * Use isDcql() to determine which form is present before calling the getters.
 *
 * Serializes as a JSON array so the round-trip with {@code SelectedCredentialsDeserializer}
 * is consistent.
 */
@Getter
@JsonSerialize(using = SelectedCredentialsSerializer.class)
public class SelectedCredentials {

    private final List<String> credentialIds;
    private final List<DcqlCredentialSelection> dcqlSelections;
    private final boolean dcql;

    /** Construct a Draft-23 instance (array of strings). */
    public static SelectedCredentials ofStrings(List<String> credentialIds) {
        return new SelectedCredentials(credentialIds, null, false);
    }

    /** Construct a DCQL instance (array of objects). */
    public static SelectedCredentials ofDcql(List<DcqlCredentialSelection> dcqlSelections) {
        return new SelectedCredentials(null, dcqlSelections, true);
    }

    private SelectedCredentials(List<String> credentialIds,
                                 List<DcqlCredentialSelection> dcqlSelections,
                                 boolean dcql) {
        this.credentialIds = credentialIds;
        this.dcqlSelections = dcqlSelections;
        this.dcql = dcql;
    }

    public boolean isEmpty() {
        if (dcql) {
            return dcqlSelections == null || dcqlSelections.isEmpty();
        }
        return credentialIds == null || credentialIds.isEmpty();
    }
}
