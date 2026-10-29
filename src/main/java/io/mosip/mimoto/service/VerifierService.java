package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.openID4VP.authorizationRequest.Verifier;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;

public interface VerifierService {
    Optional<VerifierDTO> getVerifierByClientId(String clientId) throws ApiNotAccessibleException, IOException;
    VerifierDTO validateVerifier(String clientId, String responseUri, String redirectUri) throws ApiNotAccessibleException, IOException;

    /**
     * Returns {@code redirectUri} when it is a trusted post-Direct-Post target for {@code clientId}.
     * Matching ignores the fragment (and query), requires the same origin as a registered
     * {@code redirect_uris} entry, and allows a path under that registered URI.
     * Returns null when the redirect URI is blank, the client is unknown, or no registered URI matches.
     */
    String verifyRedirectUri(String clientId, String redirectUri);
    VerifiersDTO getTrustedVerifiers() throws ApiNotAccessibleException, IOException;
    boolean isVerifierTrustedByWallet(String verifierId, String walletId);
    boolean isVerifierClientPreregistered(List<Verifier> preRegisteredVerifiers, String urlEncodedVPAuthorizationRequest) throws URISyntaxException;
}
