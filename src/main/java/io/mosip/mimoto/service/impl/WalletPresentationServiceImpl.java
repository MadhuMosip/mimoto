package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.constant.OpenID4VPConstants;
import io.mosip.mimoto.constant.SigningAlgorithm;
import io.mosip.mimoto.constant.SpecVersion;
import io.mosip.mimoto.dto.*;
import io.mosip.mimoto.dto.MatchingCredentialsDTO;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.model.VerifiablePresentation;
import io.mosip.mimoto.repository.VerifiablePresentationsRepository;
import io.mosip.mimoto.service.CredentialMatchingService;
import io.mosip.mimoto.service.KeyPairRetrievalService;
import io.mosip.mimoto.service.VerifierService;
import io.mosip.mimoto.service.WalletPresentationService;
import io.mosip.mimoto.util.SigningKeyUtil;
import io.mosip.mimoto.util.Utilities;
import io.mosip.mimoto.util.UrlParameterUtils;
import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest;
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.authorizationRequest.Verifier;
import io.mosip.openID4VP.dcql.query.CredentialQuery;
import io.mosip.openID4VP.dcql.query.CredentialSetQuery;
import io.mosip.openID4VP.dcql.query.DCQLQuery;
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken;
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult;
import io.mosip.openID4VP.constants.FormatType;
import io.mosip.openID4VP.verifier.VerifierResponse;
import io.mosip.openID4VP.wallet.Credential;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.lang.IllegalArgumentException;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

import static io.mosip.mimoto.exception.ErrorConstants.*;

/**
 * Handles the full OpenID4VP wallet-side presentation flow for both
 * Draft-23 (Presentation Exchange) and OVP 1.0 (DCQL) verifiers.
 *
 * <p>Flow overview:
 * <ol>
 *   <li>POST /presentations — {@link #handleVPAuthorizationRequest}: authenticates the
 *       verifier, detects the spec version, and stores it in the session.</li>
 *   <li>GET  /presentations/{pid}/credentials — {@link #getMatchingCredentials}: delegates
 *       to {@link CredentialMatchingServiceImpl} which routes by spec version.</li>
 *   <li>PATCH /presentations/{pid} — {@link #handlePresentationAction}: submits credentials
 *       or rejects the verifier, routing by spec version from the session.</li>
 * </ol>
 */
@Slf4j
@Service
public class WalletPresentationServiceImpl implements WalletPresentationService {

    private static final String UNKNOWN_VERIFIER = "unknown";
    private static final String EMPTY_JSON = "{}";
    private static final String DEFAULT_SIGNING_ALGORITHM_NAME = "ED25519";

    private final VerifierService verifierService;

    private final OpenID4VPService openID4VPService;

    private final ObjectMapper objectMapper;

    private final KeyPairRetrievalService keyPairService;

    private final CredentialMatchingService credentialMatchingService;

    private final VerifiablePresentationsRepository verifiablePresentationsRepository;

    public WalletPresentationServiceImpl(VerifierService verifierService, OpenID4VPService openID4VPService, ObjectMapper objectMapper, KeyPairRetrievalService keyPairService, CredentialMatchingService credentialMatchingService, VerifiablePresentationsRepository verifiablePresentationsRepository) {
        this.verifierService = verifierService;
        this.openID4VPService = openID4VPService;
        this.objectMapper = objectMapper;
        this.keyPairService = keyPairService;
        this.credentialMatchingService = credentialMatchingService;
        this.verifiablePresentationsRepository = verifiablePresentationsRepository;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Step 1 — Handle authorization request  (POST /presentations)
    // ─────────────────────────────────────────────────────────────────────────

    @Override
    public VPResponseDTO handleVPAuthorizationRequest(String urlEncodedVPAuthorizationRequest, String walletId) throws ApiNotAccessibleException, IOException, URISyntaxException {
        String presentationId = UUID.randomUUID().toString();

        log.info("Starting VP authorization request for walletId={}, presentationId={}",
                walletId, presentationId);

        List<Verifier> preRegisteredVerifiers = openID4VPService.getPreRegisteredVerifiers();
        boolean shouldValidateClient = verifierService.isVerifierClientPreregistered(
                preRegisteredVerifiers, urlEncodedVPAuthorizationRequest);

        // Create an OpenID4VP instance scoped to this presentation session.
        OpenID4VP openID4VP = openID4VPService.create(
                presentationId, preRegisteredVerifiers, shouldValidateClient);

        // Authenticate the verifier — the library validates the authorization request
        // and returns a typed subclass that reveals whether it is Draft-23 or OVP 1.0.
        AuthorizationRequest authorizationRequest =
                openID4VP.authenticateVerifier(urlEncodedVPAuthorizationRequest);

        // Detect spec version from the returned request subtype.
        SpecVersion specVersion = (authorizationRequest instanceof AuthorizationDcqlRequest)
                ? SpecVersion.V1_0
                : SpecVersion.DRAFT_23;

        log.info("Detected specVersion={} for presentationId={}", specVersion, presentationId);

        VerifiablePresentationVerifierDTO verifierDTO =
                createVPResponseVerifierDTO(preRegisteredVerifiers, authorizationRequest, walletId);

        return new VPResponseDTO(presentationId, verifierDTO, specVersion);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Step 2 — Get matching credentials  (GET /presentations/{pid}/credentials)
    // ─────────────────────────────────────────────────────────────────────────

    @Override
    public MatchingCredentialsDTO getMatchingCredentials(
            VerifiablePresentationSessionData sessionData,
            String walletId,
            String base64Key) throws ApiNotAccessibleException, IOException {

        log.debug("getMatchingCredentials: walletId={}, specVersion={}",
                walletId, sessionData != null ? sessionData.getSpecVersion() : "null");
        return credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Step 3 — Submit or reject  (PATCH /presentations/{pid})
    // ─────────────────────────────────────────────────────────────────────────

    @Override
    public ResponseEntity<?> handlePresentationAction(
            String walletId,
            String presentationId,
            SubmitPresentationRequestDTO request,
            VerifiablePresentationSessionData vpSessionData,
            String base64Key) {

        log.info("handlePresentationAction: walletId={}, presentationId={}", walletId, presentationId);

        try {
            if (request.isSubmissionRequest()) {
                log.info("Processing submission for presentationId={}", presentationId);
                if (base64Key == null || base64Key.isBlank()) {
                    log.warn("Wallet key missing for submission — walletId={}", walletId);
                    return Utilities.getErrorResponseEntityWithoutWrapper(
                            new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                                    "Wallet key is required for credential presentation"),
                            INVALID_REQUEST.getErrorCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
                }
                SubmitPresentationResponseDTO response =
                        submitPresentation(vpSessionData, walletId, presentationId, request, base64Key);
                return ResponseEntity.status(HttpStatus.OK).body(response);

            } else if (request.isRejectionRequest()) {
                log.info("Processing rejection for presentationId={}", presentationId);
                return handleVerifierRejection(walletId, vpSessionData, request);

            } else {
                log.warn("Request must contain selectedCredentials (or dcqlSelections) OR errorCode+errorMessage");
                return Utilities.getErrorResponseEntityWithoutWrapper(new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Request must contain either selectedCredentials / dcqlSelections or both errorCode and errorMessage"), INVALID_REQUEST.getErrorCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
            }

        } catch (JOSEException exception) {
            log.error("JWT signing error during presentation action for walletId: {}, presentationId: {}", walletId, presentationId, exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, JWT_SIGNING_ERROR.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);

        } catch (KeyGenerationException exception) {
            log.error("Key generation/retrieval error during presentation action for walletId: {}, presentationId: {}", walletId, presentationId, exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, KEY_GENERATION_ERROR.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);

        } catch (DecryptionException exception) {
            log.error("Decryption error during presentation action for walletId: {}, presentationId: {}", walletId, presentationId, exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, DECRYPTION_ERROR.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);

        } catch (ApiNotAccessibleException | IOException exception) {
            log.error("Error during presentation action for walletId: {}, presentationId: {}", walletId, presentationId, exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, WALLET_CREATE_VP_EXCEPTION.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);

        } catch (VPErrorNotSentException exception) {
            log.error("Error sending rejection to verifier for walletId: {}, presentationId: {}", walletId, presentationId, exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, REJECT_VERIFIER_EXCEPTION.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);

        } catch (IllegalStateException exception) {
            log.error("Invalid state during presentation action for walletId: {}, presentationId: {}", walletId, presentationId, exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, WALLET_CREATE_VP_EXCEPTION.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);

        } catch (IllegalArgumentException exception) {
            log.error("Invalid argument during presentation action for walletId: {}, presentationId: {}", walletId, presentationId, exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, INVALID_REQUEST.getErrorCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Core submission logic
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Builds and sends the Verifiable Presentation to the verifier.
     *
     * <p>Routes to the Draft-23 or DCQL credential-map builder based on the session's
     * {@link SpecVersion}.  After that, both paths converge on the same library calls:
     * {@code constructUnsignedVPToken → sign → sendVPResponseToVerifier}.
     */
    public SubmitPresentationResponseDTO submitPresentation(
            VerifiablePresentationSessionData sessionData,
            String walletId,
            String presentationId,
            SubmitPresentationRequestDTO request,
            String base64Key)
            throws ApiNotAccessibleException, IOException, JOSEException,
                   KeyGenerationException, DecryptionException {

        LocalDateTime requestedAt = LocalDateTime.now();
        validateSubmissionRequest(request);

        log.info("submitPresentation: walletId={}, presentationId={}, specVersion={}",
                walletId, presentationId, sessionData.getSpecVersion());

        // Step 1 — Re-create and re-authenticate the OpenID4VP instance.
        //          The library requires authenticateVerifier() before constructUnsignedVPToken().
        List<Verifier> preRegisteredVerifiers = openID4VPService.getPreRegisteredVerifiers();
        OpenID4VP openID4VP = openID4VPService.create(
                presentationId, preRegisteredVerifiers, sessionData.isVerifierClientPreregistered());
        openID4VP.authenticateVerifier(sessionData.getAuthorizationRequest());

        // Step 2 — Build Map<queryId_or_descriptorId, List<Credential>> for the library.
        //          The map key tells the library which query/descriptor each credential satisfies.
        Map<String, List<Credential>> credentialMap;
        if (request.isDcqlSubmission()) {
            validateDcqlSelections(request, sessionData);
            credentialMap = buildQueryCredentialMap(request.getDcqlSelections(), sessionData);
        } else {
            List<DecryptedCredentialDTO> selected =
                    fetchSelectedCredentials(sessionData, request.getSelectedCredentialIds());
            credentialMap = buildDescriptorCredentialMap(selected);
        }

        // Step 3 — Ask the library to prepare the unsigned VP token(s).
        //          Returns one UnsignedVPToken per format/key-reference combination.
        List<UnsignedVPToken> unsignedVPTokens = openID4VP.constructUnsignedVPToken(credentialMap);

        // Step 4 — Sign each token using the wallet's private key.
        SigningAlgorithm signingAlgorithm = SigningAlgorithm.valueOf(DEFAULT_SIGNING_ALGORITHM_NAME);
        KeyPair keyPair = keyPairService.getKeyPairFromDB(walletId, base64Key, signingAlgorithm);
        List<VPTokenSigningResult> signingResults = signVPTokens(unsignedVPTokens, keyPair, signingAlgorithm);

        // Step 5 — Send the signed VP to the verifier.
        try {
            VerifierResponse response = openID4VP.sendVPResponseToVerifier(signingResults);
            boolean success = response.getStatusCode() >= 200 && response.getStatusCode() < 300;
            storePresentationRecord(walletId, presentationId, request, sessionData, success, requestedAt);
            return SubmitPresentationResponseDTO.builder()
                    .redirectUri(response.getRedirectUri())
                    .status(success ? OpenID4VPConstants.STATUS_SUCCESS : OpenID4VPConstants.STATUS_ERROR)
                    .message(success ? OpenID4VPConstants.MESSAGE_PRESENTATION_SUCCESS
                                     : OpenID4VPConstants.MESSAGE_PRESENTATION_SHARE_FAILED)
                    .build();
        } catch (Exception ex) {
            log.error("Failed to send VP to verifier for presentationId={}", presentationId, ex);
            storePresentationRecord(walletId, presentationId, request, sessionData, false, requestedAt);
            return SubmitPresentationResponseDTO.builder()
                    .status(OpenID4VPConstants.STATUS_ERROR)
                    .message(OpenID4VPConstants.MESSAGE_PRESENTATION_SHARE_FAILED)
                    .build();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Credential-map builders
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Draft-23: builds {@code Map<descriptorId, List<Credential>>}.
     *
     * <p>The library uses the map key as the {@code InputDescriptor.id} reference when
     * constructing the VP token and the {@code descriptor_map} in the response.
     * Each {@link DecryptedCredentialDTO} carries the {@code descriptorId} set during
     * the credential-matching step.
     */
    private Map<String, List<Credential>> buildDescriptorCredentialMap(
            List<DecryptedCredentialDTO> selectedCredentials) {

        Map<String, List<Credential>> result = new LinkedHashMap<>();

        for (DecryptedCredentialDTO dto : selectedCredentials) {
            // Fall back to the credential's own id if descriptorId was not set.
            String key = (dto.getDescriptorId() != null && !dto.getDescriptorId().isBlank())
                    ? dto.getDescriptorId()
                    : dto.getId();

            VCCredentialResponse vc = dto.getCredential();
            FormatType format = mapToFormatType(vc.getFormat());
            Credential credential = new Credential(format, vc.getCredential(), dto.getId());
            result.computeIfAbsent(key, k -> new ArrayList<>()).add(credential);
        }

        log.debug("buildDescriptorCredentialMap: {} descriptor(s) → {} credential(s)",
                result.size(), result.values().stream().mapToInt(List::size).sum());
        return result;
    }

    /**
     * OVP 1.0 / DCQL: builds {@code Map<queryId, List<Credential>>}.
     *
     * <p>The map key is the DCQL {@code CredentialQuery.id} supplied by the user in their
     * {@link DcqlCredentialSelection} entries.  The library uses this to satisfy each
     * {@code dcql_query.credentials[i]} requirement.
     */
    private Map<String, List<Credential>> buildQueryCredentialMap(
            List<DcqlCredentialSelection> dcqlSelections,
            VerifiablePresentationSessionData sessionData) {

        // Build a quick lookup of all cached credentials by their wallet id.
        Map<String, DecryptedCredentialDTO> credentialCache = Optional
                .ofNullable(sessionData.getMatchingCredentials())
                .orElse(Collections.emptyList())
                .stream()
                .collect(Collectors.toMap(
                        DecryptedCredentialDTO::getId,
                        dto -> dto,
                        (first, second) -> first,
                        LinkedHashMap::new));

        Map<String, List<Credential>> result = new LinkedHashMap<>();

        for (DcqlCredentialSelection selection : dcqlSelections) {
            List<Credential> credentials = selection.getSelectedCredentialIds().stream()
                    .map(vcId -> {
                        DecryptedCredentialDTO dto = credentialCache.get(vcId);
                        if (dto == null) {
                            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                                    "Selected credential not found in session cache: " + vcId);
                        }
                        FormatType format = mapToFormatType(dto.getCredential().getFormat());
                        return new Credential(format, dto.getCredential().getCredential(), dto.getId());
                    })
                    .collect(Collectors.toList());

            result.put(selection.getQueryId(), credentials);
        }

        log.debug("buildQueryCredentialMap: {} query(ies) → {} credential(s)",
                result.size(), result.values().stream().mapToInt(List::size).sum());
        return result;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DCQL validation
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Enforces OVP 1.0 / DCQL submission rules before the presentation is built:
     * <ul>
     *   <li>A query with {@code multiple=false} must not have more than one selected
     *       credential.</li>
     *   <li>Every required {@code credential_set} must have at least one option where
     *       all referenced query IDs have at least one selected credential.</li>
     * </ul>
     */
    private void validateDcqlSelections(
            SubmitPresentationRequestDTO request,
            VerifiablePresentationSessionData sessionData)
            throws ApiNotAccessibleException, IOException {

        DCQLQuery dcqlQuery = openID4VPService.resolveDcqlQuery(
                sessionData.getPresentationId(),
                sessionData.getAuthorizationRequest(),
                sessionData.isVerifierClientPreregistered());

        if (dcqlQuery == null) {
            log.warn("validateDcqlSelections: DCQL query is null — skipping validation");
            return;
        }

        // Map queryId → number of credentials the user selected for it.
        Map<String, Integer> selectionCount = request.getDcqlSelections().stream()
                .collect(Collectors.toMap(
                        DcqlCredentialSelection::getQueryId,
                        s -> s.getSelectedCredentialIds() != null
                                ? s.getSelectedCredentialIds().size() : 0));

        // Rule: multiple=false means at most one credential per query.
        for (CredentialQuery query : dcqlQuery.getCredentials()) {
            if (!query.getMultiple()) {
                int count = selectionCount.getOrDefault(query.getId(), 0);
                if (count > 1) {
                    throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                            "DCQL query '" + query.getId() + "' has multiple=false "
                            + "but " + count + " credential(s) were selected.");
                }
            }
        }

        // Rule: every required credential_set must be satisfied.
        if (dcqlQuery.getCredentialSets() != null) {
            for (CredentialSetQuery setQuery : dcqlQuery.getCredentialSets()) {
                if (!setQuery.getRequired()) continue;
                boolean anySatisfied = setQuery.getOptions().stream()
                        .anyMatch(option -> option.stream()
                                .allMatch(qid -> selectionCount.getOrDefault(qid, 0) > 0));
                if (!anySatisfied) {
                    throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                            "A mandatory credential_set is not satisfied. "
                            + "Options: " + setQuery.getOptions());
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Signing
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Signs each {@link UnsignedVPToken} returned by the library.
     *
     * <p>The library provides the {@code signatureAlgorithm} string per token (e.g.
     * {@code "EdDSA"}).  We honour that value and fall back to the wallet's default
     * algorithm only when the library leaves it blank.
     *
     * <p>Returns raw signature bytes ({@link VPTokenSigningResult#getSignedData()}) as
     * expected by {@link OpenID4VP#sendVPResponseToVerifier}.
     */
    private List<VPTokenSigningResult> signVPTokens(
            List<UnsignedVPToken> unsignedVPTokens,
            KeyPair keyPair,
            SigningAlgorithm defaultAlgorithm) throws JOSEException {

        log.debug("signVPTokens: signing {} token(s)", unsignedVPTokens.size());
        List<VPTokenSigningResult> results = new ArrayList<>();

        for (UnsignedVPToken token : unsignedVPTokens) {
            // For SD-JWT, the library provides a signatureAlgorithm (e.g. ES256) per token.
            // For LDP VCs, it provides EdDSA. We sign the provided dataToSign bytes directly.
            results.add(signToken(token, keyPair, defaultAlgorithm));
        }

        return results;
    }

    /**
     * Signs a single LDP_VC token.
     *
     * <p>Uses Nimbus {@link JWSSigner} to produce the raw signature bytes.
     * {@link JWSSigner#sign(com.nimbusds.jose.JWSHeader, byte[])} takes the data-to-sign
     * bytes from the library, signs them with the wallet key, and returns a
     * {@link Base64URL}-encoded signature.  {@code decode()} converts that to raw bytes,
     * which is exactly what {@link VPTokenSigningResult} expects.
     */
    private VPTokenSigningResult signToken(
            UnsignedVPToken token,
            KeyPair keyPair,
            SigningAlgorithm defaultAlgorithm) throws JOSEException {

        String algorithmName = Optional.ofNullable(token.getSignatureAlgorithm())
                .filter(s -> !s.isBlank())
                .orElse(defaultAlgorithm.getJWSAlgorithm().getName());

        JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(algorithmName);
        JWK jwk = SigningKeyUtil.generateJwk(defaultAlgorithm, keyPair);
        JWSSigner signer = SigningKeyUtil.createSigner(defaultAlgorithm, jwk);

        Base64URL signature = signer.sign(new com.nimbusds.jose.JWSHeader(jwsAlgorithm),
                token.getDataToSign());
        return new VPTokenSigningResult(signature.decode());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Rejection path
    // ─────────────────────────────────────────────────────────────────────────

    private ResponseEntity<SubmitPresentationResponseDTO> handleVerifierRejection(
            String walletId,
            VerifiablePresentationSessionData vpSessionData,
            SubmitPresentationRequestDTO request) throws VPErrorNotSentException {

        log.debug("handleVerifierRejection: walletId={}", walletId);
        ErrorDTO errorPayload = new ErrorDTO();
        errorPayload.setErrorCode(request.getErrorCode());
        errorPayload.setErrorMessage(request.getErrorMessage());
        SubmitPresentationResponseDTO response = rejectVerifier(walletId, vpSessionData, errorPayload);
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    private SubmitPresentationResponseDTO rejectVerifier(
            String walletId,
            VerifiablePresentationSessionData vpSessionData,
            ErrorDTO payload) throws VPErrorNotSentException {
        try {
            VerifierResponse verifierResponse = openID4VPService.sendErrorToVerifier(vpSessionData, payload);
            log.info("Sent rejection to verifier for walletId={}", walletId);
            SubmitPresentationResponseDTO result = new SubmitPresentationResponseDTO();
            result.setStatus(REJECTED_VERIFIER.getErrorCode());
            result.setMessage(REJECTED_VERIFIER.getErrorMessage());
            result.setRedirectUri(verifierResponse.getRedirectUri());
            return result;
        } catch (ApiNotAccessibleException | IOException | URISyntaxException | IllegalArgumentException ex) {
            log.error("Failed to send rejection to verifier for walletId={}", walletId, ex);
            throw new VPErrorNotSentException("Failed to send rejection to verifier — " + ex.getMessage());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Session helpers
    // ─────────────────────────────────────────────────────────────────────────
    // ─────────────────────────────────────────────────────────────────────────
    // Session helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Looks up credentials from the session cache by their wallet IDs.
     * The session cache was populated during the GET /credentials step.
     */
    private List<DecryptedCredentialDTO> fetchSelectedCredentials(
            VerifiablePresentationSessionData sessionData,
            List<String> selectedCredentialIds) {

        if (sessionData == null) {
            throw new IllegalStateException("Session data is null — cannot fetch credentials");
        }
        if (sessionData.getMatchingCredentials() == null) {
            throw new IllegalStateException("No matching credentials in session cache — "
                    + "GET /credentials must be called before submitting");
        }

        log.debug("fetchSelectedCredentials: resolving {} ids from {} cached credentials",
                selectedCredentialIds.size(), sessionData.getMatchingCredentials().size());

        return sessionData.getMatchingCredentials().stream()
                .filter(dto -> selectedCredentialIds.contains(dto.getId()))
                .collect(Collectors.toList());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Verifier DTO builder
    // ─────────────────────────────────────────────────────────────────────────

    private VerifiablePresentationVerifierDTO createVPResponseVerifierDTO(
            List<Verifier> preRegisteredVerifiers,
            AuthorizationRequest authorizationRequest,
            String walletId) {

        boolean isPreRegistered = preRegisteredVerifiers.stream()
                .map(Verifier::getClientId)
                .anyMatch(id -> id.equals(authorizationRequest.getClientId()));
        boolean isTrusted = verifierService.isVerifierTrustedByWallet(
                authorizationRequest.getClientId(), walletId);
        String clientName = resolveClientName(authorizationRequest)
                .filter(name -> !name.isBlank())
                .orElse(authorizationRequest.getClientId());
        String logo = resolveClientLogo(authorizationRequest).orElse(null);

        return new VerifiablePresentationVerifierDTO(
                authorizationRequest.getClientId(), clientName, logo,
                isTrusted, isPreRegistered, authorizationRequest.getRedirectUri());
    }

    private Optional<String> resolveClientName(AuthorizationRequest authorizationRequest) {
        if (authorizationRequest instanceof AuthorizationDcqlRequest dcql) {
            return Optional.ofNullable(dcql.getClientMetadata()).map(m -> m.getClientName());
        }
        if (authorizationRequest instanceof AuthorizationPresentationExchangeRequest pe) {
            return Optional.ofNullable(pe.getClientMetadata()).map(m -> m.getClientName());
        }
        return Optional.empty();
    }

    private Optional<String> resolveClientLogo(AuthorizationRequest authorizationRequest) {
        if (authorizationRequest instanceof AuthorizationDcqlRequest dcql) {
            return Optional.ofNullable(dcql.getClientMetadata()).map(m -> m.getLogoUri());
        }
        if (authorizationRequest instanceof AuthorizationPresentationExchangeRequest pe) {
            return Optional.ofNullable(pe.getClientMetadata()).map(m -> m.getLogoUri());
        }
        return Optional.empty();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Persistence helpers
    // ─────────────────────────────────────────────────────────────────────────

    private void storePresentationRecord(
            String walletId,
            String presentationId,
            SubmitPresentationRequestDTO request,
            VerifiablePresentationSessionData sessionData,
            boolean success,
            LocalDateTime requestedAt) {

        try {
            if (sessionData == null) {
                log.warn("storePresentationRecord: sessionData is null for presentationId={}", presentationId);
                return;
            }
            String verifierId = extractVerifierId(sessionData);
            String authRequest = extractVerifierAuthRequest(sessionData);
            String presentationData = createPresentationData(request);

            VerifiablePresentation record = VerifiablePresentation.builder()
                    .id(presentationId)
                    .walletId(walletId)
                    .authRequest(authRequest)
                    .presentationData(presentationData)
                    .verifierId(verifierId)
                    .status(success ? OpenID4VPConstants.STATUS_SUCCESS : OpenID4VPConstants.STATUS_ERROR)
                    .requestedAt(requestedAt)
                    .consent(true)
                    .build();

            verifiablePresentationsRepository.save(record);
            log.info("Stored presentation record: presentationId={}, walletId={}, status={}",
                    presentationId, walletId, record.getStatus());

        } catch (Exception ex) {
            log.error("CRITICAL: failed to store presentation record for presentationId={}, walletId={}",
                    presentationId, walletId, ex);
        }
    }

    private String extractVerifierId(VerifiablePresentationSessionData sessionData) {
        try {
            if (sessionData.getAuthorizationRequest() != null) {
                return UrlParameterUtils.extractQueryParameter(
                        sessionData.getAuthorizationRequest(), OpenID4VPConstants.CLIENT_ID_PARAM);
            }
        } catch (Exception ex) {
            log.warn("extractVerifierId: failed", ex);
        }
        return UNKNOWN_VERIFIER;
    }

    private String extractVerifierAuthRequest(VerifiablePresentationSessionData sessionData) {
        try {
            if (sessionData.getAuthorizationRequest() != null) {
                Map<String, Object> data = new HashMap<>();
                data.put(OpenID4VPConstants.AUTHORIZATION_REQUEST_URL, sessionData.getAuthorizationRequest());
                return objectMapper.writeValueAsString(data);
            }
        } catch (Exception ex) {
            log.warn("extractVerifierAuthRequest: failed", ex);
        }
        return EMPTY_JSON;
    }

    private String createPresentationData(SubmitPresentationRequestDTO request) {
        try {
            Map<String, Object> data = new HashMap<>();
            data.put(OpenID4VPConstants.SELECTED_CREDENTIALS, request.getSelectedCredentialIds());
            return objectMapper.writeValueAsString(data);
        } catch (Exception ex) {
            log.warn("createPresentationData: failed", ex);
            return EMPTY_JSON;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Format helper
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Converts a credential format string (e.g. {@code "ldp_vc"}) to the library's
     * {@link FormatType} enum.  Throws {@link InvalidRequestException} for unsupported formats.
     */
    private FormatType mapToFormatType(String format) {
        if (format == null) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                    "Credential format is required");
        }
        if (CredentialFormat.LDP_VC.getFormat().equalsIgnoreCase(format)) {
            return FormatType.LDP_VC;
        }
        if (CredentialFormat.VC_SD_JWT.getFormat().equalsIgnoreCase(format)) {
            return FormatType.VC_SD_JWT;
        }
        if (CredentialFormat.DC_SD_JWT.getFormat().equalsIgnoreCase(format)) {
            return FormatType.DC_SD_JWT;
        }
        throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                "Unsupported credential format: " + format + ".  Supported: ldp_vc, vc+sd-jwt, dc+sd-jwt.");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Validation
    // ─────────────────────────────────────────────────────────────────────────

    private void validateSubmissionRequest(SubmitPresentationRequestDTO request) {
        if (request == null) {
            throw new IllegalArgumentException("Request must not be null");
        }
        boolean hasDraft23 = request.getSelectedCredentialIds() != null
                && !request.getSelectedCredentialIds().isEmpty();
        boolean hasDcql = request.getDcqlSelections() != null
                && !request.getDcqlSelections().isEmpty();
        if (!hasDraft23 && !hasDcql) {
            throw new IllegalArgumentException(
                    "selectedCredentials (Draft-23) or dcqlSelections (OVP 1.0) must not be empty");
        }
    }
}
