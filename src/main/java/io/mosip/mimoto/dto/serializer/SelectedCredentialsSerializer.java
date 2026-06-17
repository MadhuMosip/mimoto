package io.mosip.mimoto.dto.serializer;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import io.mosip.mimoto.dto.SelectedCredentials;

import java.io.IOException;

/**
 * Serializes {@link SelectedCredentials} back to the same compact array form that
 * {@code SelectedCredentialsDeserializer} reads:
 * <ul>
 *   <li>Draft-23: {@code ["credId1", "credId2", ...]}</li>
 *   <li>DCQL:     {@code [{"queryId":"q1","selectedCredentialIds":["credId1"]}, ...]}</li>
 * </ul>
 * Keeping serialization and deserialization symmetric allows test code to round-trip
 * a DTO through {@code ObjectMapper} without any loss of fidelity.
 */
public class SelectedCredentialsSerializer extends StdSerializer<SelectedCredentials> {

    public SelectedCredentialsSerializer() {
        super(SelectedCredentials.class);
    }

    @Override
    public void serialize(SelectedCredentials value, JsonGenerator gen, SerializerProvider provider)
            throws IOException {
        gen.writeStartArray();
        if (value.isDcql()) {
            // DCQL form: each element is a DcqlCredentialSelection object
            for (var selection : value.getDcqlSelections()) {
                gen.writeObject(selection);
            }
        } else {
            // Draft-23 form: each element is a plain credential ID string
            for (String credId : value.getCredentialIds()) {
                gen.writeString(credId);
            }
        }
        gen.writeEndArray();
    }
}
