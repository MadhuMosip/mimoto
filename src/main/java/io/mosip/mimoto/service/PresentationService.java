package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.openID4VP.constants.SpecVersion;

import java.io.IOException;

public interface PresentationService {

    String processVPRequest(PresentationRequestDTO presentationRequestDTO, SpecVersion specVersion) throws ApiNotAccessibleException, IOException;

    /**
     * Posts an authorization error to the verifier {@code response_uri} and returns the URL
     * the browser should be redirected to, if it is registered for {@code clientId}.
     * The verifier response {@code redirect_uri} is used when present.
     */
    String submitErrorToResponseUri(String clientId, String responseUri, String redirectUri, String state,
                                     String errorCode, String errorDescription);

    /**
     * After Direct Post the verifier may return a redirect URI with an extra path and
     * {@code #response_code}. Return that URI if it belongs to this client's registered
     * {@code redirect_uris} (same host, path under the registered URI). Fragment and query
     * are ignored for the check. Return {@code null} if it is not registered.
     */
    String verifyRedirectUri(String clientId, String redirectUri);
}
