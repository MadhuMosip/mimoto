package io.mosip.mimoto.dto.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import io.mosip.mimoto.dto.DcqlCredentialSelection;
import io.mosip.mimoto.dto.SelectedCredentials;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Deserializes the selectedCredentials JSON array into a SelectedCredentials wrapper.
 *
 * Two accepted shapes:
 *   ["vc-uuid-1", "vc-uuid-2"]
 *       → SelectedCredentials.ofStrings(...)   (Draft-23)
 *
 *   [{ "queryId": "pid_query", "selectedCredentialIds": ["vc-uuid-1"] }, ...]
 *       → SelectedCredentials.ofDcql(...)       (OVP 1.0 / DCQL)
 *
 * Detection: peek at the first element. STRING token → Draft-23. START_OBJECT token → DCQL.
 */
public class SelectedCredentialsDeserializer extends StdDeserializer<SelectedCredentials> {

    public SelectedCredentialsDeserializer() {
        super(SelectedCredentials.class);
    }

    @Override
    public SelectedCredentials deserialize(JsonParser p, DeserializationContext ctx) throws IOException {
        if (p.currentToken() != JsonToken.START_ARRAY) {
            throw ctx.wrongTokenException(p, SelectedCredentials.class, JsonToken.START_ARRAY,
                    "selectedCredentials must be a JSON array");
        }

        JsonToken first = p.nextToken();

        if (first == JsonToken.END_ARRAY) {
            return SelectedCredentials.ofStrings(new ArrayList<>());
        }

        if (first == JsonToken.VALUE_STRING) {
            List<String> ids = new ArrayList<>();
            ids.add(p.getText());
            while (p.nextToken() != JsonToken.END_ARRAY) {
                ids.add(p.getText());
            }
            return SelectedCredentials.ofStrings(ids);
        }

        if (first == JsonToken.START_OBJECT) {
            List<DcqlCredentialSelection> selections = new ArrayList<>();
            do {
                selections.add(ctx.readValue(p, DcqlCredentialSelection.class));
            } while (p.nextToken() != JsonToken.END_ARRAY);
            return SelectedCredentials.ofDcql(selections);
        }

        throw ctx.wrongTokenException(p, SelectedCredentials.class, first,
                "selectedCredentials elements must be strings (Draft-23) or objects (DCQL)");
    }
}
