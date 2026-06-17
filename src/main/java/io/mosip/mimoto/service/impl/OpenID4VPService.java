package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.VerifierService;
import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest;
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.authorizationRequest.LdpVpFormatSupported;
import io.mosip.openID4VP.authorizationRequest.SdJwtVpFormatSupported;
import io.mosip.openID4VP.authorizationRequest.VPFormatSupported;
import io.mosip.openID4VP.authorizationRequest.Verifier;
import io.mosip.openID4VP.authorizationRequest.WalletConfig;
import io.mosip.openID4VP.dcql.query.DCQLQuery;
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition;
import io.mosip.openID4VP.common.OpenID4VPErrorCodes;
import io.mosip.openID4VP.constants.ClientIdPrefix;
import io.mosip.openID4VP.constants.ProofType;
import io.mosip.openID4VP.constants.RequestUriMethod;
import io.mosip.openID4VP.constants.ResponseType;
import io.mosip.openID4VP.constants.VPFormatType;
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions;
import io.mosip.openID4VP.verifier.VerifierResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;

/**
 * Adapter between mimoto and the {@code inji-openid4vp} library.
 *
 * <p>Every method that needs a fresh {@link OpenID4VP} instance goes through
 * {@link #create(String, List, boolean)} so that {@link WalletConfig} is built
 * in one place and cannot be built with silent defaults.
 *
 * <p>Supports both Draft-23 (Presentation Exchange) and OVP 1.0 (DCQL) flows.
 */
@Component
@Slf4j
public class OpenID4VPService {

    private final VerifierService verifierService;

    public OpenID4VPService(VerifierService verifierService) {
        this.verifierService = verifierService;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // OpenID4VP instance factory
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Creates an {@link OpenID4VP} instance with an empty trusted-verifier list
     * and client-validation enabled (used in tests and simple scenarios).
     */
    public OpenID4VP create(String presentationId) {
        return create(presentationId, List.of(), true);
    }

    /**
     * Creates an {@link OpenID4VP} instance with the given trusted verifiers and
     * client-validation enabled.
     */
    public OpenID4VP create(String presentationId, List<Verifier> trustedVerifiers) {
        return create(presentationId, trustedVerifiers, true);
    }

    /**
     * Primary factory method.  Builds a {@link WalletConfig} with sensible
     * defaults for every field, injects the trusted verifiers, and wraps it in
     * a new {@link OpenID4VP} instance.
     *
     * @param presentationId             used as the library's traceability id
     * @param trustedVerifiers           pre-registered verifiers from the config store
     * @param validatePreRegisteredVerifier whether the library should enforce that the
     *                                    client_id is in the trusted-verifier list
     */
    public OpenID4VP create(String presentationId,
                            List<Verifier> trustedVerifiers,
                            boolean validatePreRegisteredVerifier) {

        Map<VPFormatType, VPFormatSupported> vpFormatsSupported = Map.of(
                VPFormatType.LDP_VC,
                new LdpVpFormatSupported(List.of(ProofType.Ed25519Signature2020), null),
                VPFormatType.VC_SD_JWT,
                new SdJwtVpFormatSupported(List.of("ES256", "EdDSA"), List.of("ES256", "EdDSA")),
                VPFormatType.DC_SD_JWT,
                new SdJwtVpFormatSupported(List.of("ES256", "EdDSA"), List.of("ES256", "EdDSA"))
        );

        WalletConfig walletConfig = new WalletConfig(
                vpFormatsSupported,
                // Support both pre-registered and redirect_uri client_id schemes.
                List.of(ClientIdPrefix.PRE_REGISTERED, ClientIdPrefix.REDIRECT_URI),
                // Use the library's default signing algorithm list (null = use defaults).
                null,
                // Use the library's default encryption algorithm list (null = use defaults).
                null,
                // Use the library's default content-encryption algorithm list (null = use defaults).
                null,
                // Wallet accepts vp_token response type.
                List.of(ResponseType.VP_TOKEN),
                // Allow the verifier to reference a presentation_definition by URI.
                true,
                // Support both GET and POST for request_uri resolution.
                List.of(RequestUriMethod.GET, RequestUriMethod.POST),
                trustedVerifiers,
                validatePreRegisteredVerifier
        );

        return new OpenID4VP(presentationId, walletConfig);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Draft-23 helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Creates a fresh {@link OpenID4VP} instance, authenticates the verifier's
     * authorization request, and returns the {@link PresentationDefinition} for
     * Draft-23 requests.
     *
     * @return the {@code PresentationDefinition}, or {@code null} when the
     *         authorization request is OVP 1.0 / DCQL or inputs are null.
     */
    public PresentationDefinition resolvePresentationDefinition(
            String presentationId,
            String authRequest,
            boolean isVerifierClientPreregistered) throws ApiNotAccessibleException, IOException {

        if (presentationId == null || authRequest == null) {
            log.warn("resolvePresentationDefinition: presentationId or authRequest is null — skipping");
            return null;
        }

        List<Verifier> preRegisteredVerifiers = getPreRegisteredVerifiers();
        OpenID4VP openID4VP = create(presentationId, preRegisteredVerifiers, isVerifierClientPreregistered);
        AuthorizationRequest authorizationRequest = openID4VP.authenticateVerifier(authRequest);

        if (authorizationRequest instanceof AuthorizationPresentationExchangeRequest peRequest) {
            return peRequest.getPresentationDefinition();
        }

        log.debug("resolvePresentationDefinition: auth request is not a Draft-23 request — returning null");
        return null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // OVP 1.0 / DCQL helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Creates a fresh {@link OpenID4VP} instance, authenticates the verifier's
     * authorization request, and returns the {@link DCQLQuery} for OVP 1.0 requests.
     *
     * @return the {@code DCQLQuery}, or {@code null} when the authorization request
     *         is Draft-23 or inputs are null.
     */
    public DCQLQuery resolveDcqlQuery(
            String presentationId,
            String authRequest,
            boolean isVerifierClientPreregistered) throws ApiNotAccessibleException, IOException {

        if (presentationId == null || authRequest == null) {
            log.warn("resolveDcqlQuery: presentationId or authRequest is null — skipping");
            return null;
        }

        List<Verifier> preRegisteredVerifiers = getPreRegisteredVerifiers();
        OpenID4VP openID4VP = create(presentationId, preRegisteredVerifiers, isVerifierClientPreregistered);
        AuthorizationRequest authorizationRequest = openID4VP.authenticateVerifier(authRequest);

        if (authorizationRequest instanceof AuthorizationDcqlRequest dcqlRequest) {
            return dcqlRequest.getDcqlQuery();
        }

        log.debug("resolveDcqlQuery: auth request is not an OVP 1.0 request — returning null");
        return null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Error forwarding
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Reconstructs an {@link OpenID4VP} instance from the session, re-authenticates
     * the verifier (to populate the library's internal state), and then forwards the
     * wallet-side error to the verifier using {@link OpenID4VP#sendErrorInfoToVerifier}.
     */
    public VerifierResponse sendErrorToVerifier(
            VerifiablePresentationSessionData sessionData,
            ErrorDTO payload) throws ApiNotAccessibleException, IOException, URISyntaxException {

        if (sessionData == null
                || sessionData.getPresentationId() == null
                || sessionData.getAuthorizationRequest() == null) {
            throw new IllegalArgumentException("Invalid presentation session data: presentationId and authorizationRequest are required");
        }

        List<Verifier> preRegisteredVerifiers = getPreRegisteredVerifiers();
        log.info("Creating OpenID4VP instance to send error to verifier. presentationId={}, preRegisteredVerifiers={}, isVerifierClientPreregistered={}",
                sessionData.getPresentationId(), preRegisteredVerifiers, sessionData.isVerifierClientPreregistered());
        OpenID4VP openID4VP = create(
                sessionData.getPresentationId(),
                preRegisteredVerifiers,
                sessionData.isVerifierClientPreregistered());

        // Re-authenticate to hydrate the library's internal response URI state.
        openID4VP.authenticateVerifier(sessionData.getAuthorizationRequest());

        Exception errorForVerifier = toOpenID4VPException(payload);
        VerifierResponse verifierResponse = openID4VP.sendErrorInfoToVerifier(errorForVerifier);
        log.info("Sent error to verifier for presentationId={}. Response: {}",
                sessionData.getPresentationId(), verifierResponse);
        return verifierResponse;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Fetches the current trusted-verifier list from the config store and converts
     * each entry to the library's {@link Verifier} type.
     */
    public List<Verifier> getPreRegisteredVerifiers() throws ApiNotAccessibleException, IOException {
        return verifierService.getTrustedVerifiers().getVerifiers().stream()
                .map(v -> new Verifier(
                        v.getClientId(),
                        v.getResponseUris(),
                        v.getJwksUri(),
                        v.getAllowUnsignedRequest()))
                .toList();
    }

    /**
     * Maps a wallet {@link ErrorDTO} to the matching {@link OpenID4VPExceptions} subtype
     * so the library can include the correct {@code error} field in the response to
     * the verifier.
     */
    private Exception toOpenID4VPException(ErrorDTO payload) {
        if (payload == null) {
            throw new IllegalArgumentException("Error payload must not be null");
        }

        String message = payload.getErrorMessage() != null ? payload.getErrorMessage() : "";
        String code = payload.getErrorCode();

        if (OpenID4VPErrorCodes.INVALID_TRANSACTION_DATA.equals(code)) {
            return new OpenID4VPExceptions.InvalidTransactionData(message, "OpenID4VPService");
        }
        // Default: use access_denied for unknown or missing codes.
        return new OpenID4VPExceptions.AccessDenied(message, "OpenID4VPService");
    }
}
