package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.constant.OpenID4VPConstants;
import io.mosip.mimoto.constant.SigningAlgorithm;
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
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest;
import io.mosip.openID4VP.authorizationRequest.Verifier;
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
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

import static io.mosip.mimoto.exception.ErrorConstants.*;

/**
 * Service implementation for handling wallet presentation operations
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

    @Override
    public VPResponseDTO handleVPAuthorizationRequest(String urlEncodedVPAuthorizationRequest, String walletId) throws ApiNotAccessibleException, IOException, URISyntaxException {
        String presentationId = UUID.randomUUID().toString();

        //Initialize OpenID4VP instance with presentationId as traceability id for each new Verifiable Presentation request
        OpenID4VP openID4VP = openID4VPService.create(presentationId);

        List<Verifier> preRegisteredVerifiers = getPreRegisteredVerifiers();
        boolean shouldValidateClient = verifierService.isVerifierClientPreregistered(preRegisteredVerifiers, urlEncodedVPAuthorizationRequest);
        AuthorizationRequest authorizationRequest = openID4VP.authenticateVerifier(urlEncodedVPAuthorizationRequest, preRegisteredVerifiers, shouldValidateClient);
        VerifiablePresentationVerifierDTO verifiablePresentationVerifierDTO = createVPResponseVerifierDTO(preRegisteredVerifiers, authorizationRequest, walletId);

        String specVersion = (authorizationRequest instanceof AuthorizationDcqlRequest) ? "v1" : "draft-23";
        return new VPResponseDTO(presentationId, specVersion, verifiablePresentationVerifierDTO);
    }

    @Override
    public MatchingCredentialsDTO getMatchingCredentials(VerifiablePresentationSessionData sessionData, String walletId, String base64Key) throws ApiNotAccessibleException, IOException {
        log.debug("Getting matching credentials for walletId: {}, presentationId: {}", walletId, sessionData != null ? sessionData.getPresentationId() : "null");
        return credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);
    }

    @Override
    public ResponseEntity<?> handlePresentationAction(String walletId, String presentationId, SubmitPresentationRequestDTO request, VerifiablePresentationSessionData vpSessionData, String base64Key) {

        log.info("Processing presentation action for walletId: {}, presentationId: {}", walletId, presentationId);

        try {
            // Determine the action based on request content
            if (request.isSubmissionRequest()) {
                log.info("Processing presentation submission for presentationId: {}", presentationId);
                return handlePresentationSubmission(walletId, presentationId, request, vpSessionData, base64Key);

            } else if (request.isRejectionRequest()) {
                log.info("Processing verifier rejection for presentationId: {}", presentationId);
                return handleVerifierRejection(walletId, vpSessionData, request);

            } else {
                log.warn("Invalid request format - must contain either selectedCredentials or both errorCode and errorMessage");
                return Utilities.getErrorResponseEntityWithoutWrapper(new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Request must contain either selectedCredentials or both errorCode and errorMessage"), INVALID_REQUEST.getErrorCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
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

    /**
     * Creates a VerifiablePresentationVerifierDTO from the authorization request
     */
    private VerifiablePresentationVerifierDTO createVPResponseVerifierDTO(List<Verifier> preRegisteredVerifiers, AuthorizationRequest authorizationRequest, String walletId) {
        boolean isVerifierPreRegisteredWithWallet = preRegisteredVerifiers.stream().map(Verifier::getClientId).toList().contains(authorizationRequest.getClientId());
        boolean isVerifierTrustedByWallet = verifierService.isVerifierTrustedByWallet(authorizationRequest.getClientId(), walletId);
        // Newer OpenID4VP library does not expose parsed client_metadata on AuthorizationRequest.
        // We keep UI backward compatible by defaulting display fields to client_id.
        String clientName = authorizationRequest.getClientId();
        String logo = null;
        return new VerifiablePresentationVerifierDTO(
                authorizationRequest.getClientId(),
                clientName,
                logo,
                isVerifierTrustedByWallet,
                isVerifierPreRegisteredWithWallet,
                authorizationRequest.getRedirectUri()
        );
    }

    /**
     * Gets the list of pre-registered verifiers
     */
    private List<Verifier> getPreRegisteredVerifiers() throws ApiNotAccessibleException, IOException {
        return verifierService.getTrustedVerifiers().getVerifiers().stream().map(verifierDTO -> new Verifier(verifierDTO.getClientId(), verifierDTO.getResponseUris(), verifierDTO.getJwksUri(), verifierDTO.getAllowUnsignedRequest())).toList();
    }

    /**
     * Handles presentation submission with selected credentials
     */
    private ResponseEntity<SubmitPresentationResponseDTO> handlePresentationSubmission(String walletId, String presentationId, SubmitPresentationRequestDTO request, VerifiablePresentationSessionData sessionData, String base64Key) throws ApiNotAccessibleException, IOException, JOSEException, KeyGenerationException, DecryptionException {

        log.debug("Submitting presentation for walletId: {}, presentationId: {}", walletId, presentationId);

        if (base64Key == null || base64Key.isBlank()) {
            log.warn("Wallet key not found for walletId: {}", walletId);
            throw new IllegalArgumentException("Wallet key is required for presentation submission");
        }

        SubmitPresentationResponseDTO response = submitPresentation(sessionData, walletId, presentationId, request, base64Key);

        log.info("Presentation submission completed successfully for walletId: {}, presentationId: {}", walletId, presentationId);
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    /**
     * Handles verifier rejection with error details
     */
    private ResponseEntity<SubmitPresentationResponseDTO> handleVerifierRejection(String walletId, VerifiablePresentationSessionData vpSessionData, SubmitPresentationRequestDTO request) throws VPErrorNotSentException {

        log.debug("Rejecting verifier for walletId: {}", walletId);

        // Create ErrorDTO from the request
        ErrorDTO errorPayload = new ErrorDTO();
        errorPayload.setErrorCode(request.getErrorCode());
        errorPayload.setErrorMessage(request.getErrorMessage());

        // Reject the verifier
        SubmitPresentationResponseDTO submitPresentationResponseDTO = rejectVerifier(walletId, vpSessionData, errorPayload);

        log.info("Verifier rejection completed successfully for walletId: {}", walletId);

        return ResponseEntity.status(HttpStatus.OK).body(submitPresentationResponseDTO);
    }

    /**
     * Rejects the verifier by sending error information
     */
    private SubmitPresentationResponseDTO rejectVerifier(String walletId, VerifiablePresentationSessionData vpSessionData, ErrorDTO payload) throws VPErrorNotSentException {
        try {
            VerifierResponse verifierResponse = openID4VPService.sendErrorToVerifier(vpSessionData, payload);
            log.info("Sent rejection to verifier. Response: {}", verifierResponse);

            SubmitPresentationResponseDTO submitPresentationResponseDTO = new SubmitPresentationResponseDTO();
            submitPresentationResponseDTO.setStatus(REJECTED_VERIFIER.getErrorCode());
            submitPresentationResponseDTO.setMessage(REJECTED_VERIFIER.getErrorMessage());
            submitPresentationResponseDTO.setRedirectUri(verifierResponse.getRedirectUri());
            return submitPresentationResponseDTO;
        } catch (ApiNotAccessibleException | IOException | URISyntaxException | IllegalArgumentException e) {
            log.error("Failed to send rejection to verifier for walletId: {} - Error: {}", walletId, e.getMessage(), e);
            throw new VPErrorNotSentException("Failed to send rejection to verifier - " + e.getMessage());
        }
    }

    /**
     * Submits a presentation with selected credentials
     */
    public SubmitPresentationResponseDTO submitPresentation(VerifiablePresentationSessionData sessionData, String walletId, String presentationId, SubmitPresentationRequestDTO request, String base64Key) throws ApiNotAccessibleException, IOException, JOSEException, KeyGenerationException, DecryptionException {

        LocalDateTime requestedAt = LocalDateTime.now();

        validateInputs(request);

        log.info("Starting presentation submission for walletId: {}, presentationId: {}", walletId, presentationId);

        // Step 1: Fetch full credentials by ID from cache
        List<String> selectedCredentialIds = resolveSelectedCredentialIds(request);
        List<DecryptedCredentialDTO> selectedCredentials = fetchSelectedCredentials(sessionData, selectedCredentialIds);

        // Step 2: Create OpenID4VP instance and construct unsigned VP token
        OpenID4VP openID4VP = openID4VPService.create(presentationId);
        List<Verifier> preRegisteredVerifiers = verifierService.getTrustedVerifiers().getVerifiers().stream().map(verifierDTO -> new Verifier(verifierDTO.getClientId(), verifierDTO.getResponseUris(), verifierDTO.getJwksUri(), verifierDTO.getAllowUnsignedRequest())).toList();
        openID4VP.authenticateVerifier(sessionData.getAuthorizationRequest(), preRegisteredVerifiers, sessionData.isVerifierClientPreregistered());

        // Use configurable signing algorithm
        SigningAlgorithm signingAlgorithm = SigningAlgorithm.valueOf(DEFAULT_SIGNING_ALGORITHM_NAME);
        KeyPair keyPair = keyPairService.getKeyPairFromDB(walletId, base64Key, signingAlgorithm);
        JWK jwk = SigningKeyUtil.generateJwk(signingAlgorithm, keyPair);
        Map<String, List<Credential>> selectedCredentialsForJar =
                buildSelectedCredentialsForJar(openID4VP, sessionData, selectedCredentials, request, jwk);
        log.info("Constructing unsigned VP token for walletId: {}, presentationId: {}, selectedCredentialIds: {}", walletId, presentationId, selectedCredentialIds);
        List<UnsignedVPToken> unsignedVPTokens = openID4VP.constructUnsignedVPToken(selectedCredentialsForJar);

        // Step 3: Sign token using user's private key
        JWSSigner jwsSigner = SigningKeyUtil.createSigner(signingAlgorithm, jwk);
        List<VPTokenSigningResult> vpTokenSigningResults = signVPTokens(unsignedVPTokens, jwsSigner);

        // Step 4: Share verifiable presentation with verifier using OpenID4VP JAR
        log.debug("Calling OpenID4VP JAR's shareVerifiablePresentation method");
        try {
            VerifierResponse response = openID4VP.sendVPResponseToVerifier(vpTokenSigningResults);
            boolean shareSuccess = response.getStatusCode() >= 200 && response.getStatusCode() < 300;
            // Step 5: Store presentation record in database
            storePresentationRecord(walletId, presentationId, request, sessionData, shareSuccess, requestedAt);
            // Step 6: Return success response
            return SubmitPresentationResponseDTO.builder().redirectUri(response.getRedirectUri()).status(shareSuccess ? OpenID4VPConstants.STATUS_SUCCESS : OpenID4VPConstants.STATUS_ERROR).message(shareSuccess ? OpenID4VPConstants.MESSAGE_PRESENTATION_SUCCESS : OpenID4VPConstants.MESSAGE_PRESENTATION_SHARE_FAILED).build();
        } catch (Exception e) {
            log.error("Failed to share verifiable presentation with verifier", e);
            // Store failed presentation record
            storePresentationRecord(walletId, presentationId, request, sessionData, false, requestedAt);
            return SubmitPresentationResponseDTO.builder().redirectUri(null).status(OpenID4VPConstants.STATUS_ERROR).message(OpenID4VPConstants.MESSAGE_PRESENTATION_SHARE_FAILED).build();
        }
    }

    private List<VPTokenSigningResult> signVPTokens(List<UnsignedVPToken> unsignedVPTokens, JWSSigner jwsSigner) {
        if (unsignedVPTokens == null || unsignedVPTokens.isEmpty()) {
            throw new IllegalArgumentException("No unsigned VP tokens to sign");
        }

        return unsignedVPTokens.stream().map(unsignedVPToken -> {
            try {
                // Use algorithm requested by library (ex: "EdDSA")
                JWSAlgorithm alg = JWSAlgorithm.parse(unsignedVPToken.getSignatureAlgorithm());
                JWSHeader header = new JWSHeader.Builder(alg).build();
                Base64URL signature = jwsSigner.sign(header, unsignedVPToken.getDataToSign());
                return new VPTokenSigningResult(signature.decode());
            } catch (Exception e) {
                throw new RuntimeException("Failed to sign VP token for format: " + unsignedVPToken.getFormat(), e);
            }
        }).toList();
    }

    /**
     * Fetches selected credentials from the session cache
     */
    private List<DecryptedCredentialDTO> fetchSelectedCredentials(VerifiablePresentationSessionData sessionData, List<String> selectedCredentialIds) {

        log.debug("Fetching {} selected credentials from cache", selectedCredentialIds.size());

        if (sessionData == null) {
            throw new IllegalStateException("Session data is null - cannot fetch credentials");
        }

        if (sessionData.getMatchingCredentials() == null) {
            throw new IllegalStateException("No matching credentials found in session cache");
        }

        return sessionData.getMatchingCredentials().stream().filter(credential -> selectedCredentialIds.contains(credential.getId())).collect(Collectors.toList());
    }

    private List<String> resolveSelectedCredentialIds(SubmitPresentationRequestDTO request) {
        if (request.getSelectedCredentials() != null && !request.getSelectedCredentials().isEmpty()) {
            return request.getSelectedCredentials();
        }
        if (request.getSelectedCredentialMappings() != null && !request.getSelectedCredentialMappings().isEmpty()) {
            return request.getSelectedCredentialMappings().stream()
                    .map(SelectedCredentialMapping::getCredentialId)
                    .distinct()
                    .toList();
        }
        return Collections.emptyList();
    }

    private Map<String, List<Credential>> buildSelectedCredentialsForJar(
            OpenID4VP openID4VP,
            VerifiablePresentationSessionData sessionData,
            List<DecryptedCredentialDTO> selectedCredentials,
            SubmitPresentationRequestDTO request,
            JWK jwk
    ) throws JsonProcessingException, ApiNotAccessibleException, IOException {
        if (sessionData == null || sessionData.getSpecVersion() == null) {
            throw new IllegalStateException("Missing specVersion in session; restart presentation flow");
        }
        List<Credential> jarCredentials = selectedCredentials.stream()
                .map(this::toJarCredential)
                .toList();

        if ("v1".equalsIgnoreCase(sessionData.getSpecVersion())) {
            // v1 requires mapping credentialQueryId -> credentials
            List<SelectedCredentialMapping> mappings = request.getSelectedCredentialMappings();
            if (mappings == null || mappings.isEmpty()) {
                throw new IllegalArgumentException("selectedCredentialMappings is required for OVP v1 submissions");
            }
            Map<String, List<Credential>> byQueryId = new HashMap<>();
            for (SelectedCredentialMapping mapping : mappings) {
                Credential cred = jarCredentials.stream()
                        .filter(c -> c.getCredentialId().equals(mapping.getCredentialId()))
                        .findFirst()
                        .orElseThrow(() -> new IllegalArgumentException("Selected credential not found in session cache: " + mapping.getCredentialId()));
                byQueryId.computeIfAbsent(mapping.getCredentialQueryId(), k -> new ArrayList<>()).add(cred);
            }
            return byQueryId;
        }

        // draft-23: map inputDescriptorId -> credentials. We derive descriptor matches on submit.
        var presentationDefinition = openID4VPService.resolvePresentationDefinition(
                sessionData.getPresentationId(),
                sessionData.getAuthorizationRequest(),
                sessionData.isVerifierClientPreregistered()
        );
        if (presentationDefinition == null || presentationDefinition.getInputDescriptors() == null) {
            throw new IllegalStateException("Unable to resolve presentation definition for submission");
        }

        Map<String, List<Credential>> byInputDescriptorId = new HashMap<>();
        for (var descriptor : presentationDefinition.getInputDescriptors()) {
            List<Credential> credsForDescriptor = selectedCredentials.stream()
                    .filter(dc -> credentialMatchingService instanceof CredentialMatchingServiceImpl impl
                            ? impl.matchesInputDescriptorForSubmission(dc.getCredential(), descriptor)
                            : true)
                    .map(this::toJarCredential)
                    .toList();
            if (!credsForDescriptor.isEmpty()) {
                byInputDescriptorId.put(descriptor.getId(), credsForDescriptor);
            }
        }
        return byInputDescriptorId;
    }

    private Credential toJarCredential(DecryptedCredentialDTO decrypted) {
        VCCredentialResponse vcCredentialResponse = decrypted.getCredential();
        String credentialFormat = vcCredentialResponse.getFormat();
        FormatType formatType = mapStringToFormatType(credentialFormat);
        Object data = vcCredentialResponse.getCredential();
        return new Credential(formatType, data, decrypted.getId());
    }

    private FormatType mapStringToFormatType(String format) {
        if (format == null) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Credential format is required.");
        }
        String formatLower = format.toLowerCase();
        if (CredentialFormat.LDP_VC.getFormat().equals(formatLower)) {
            return FormatType.LDP_VC;
        }
        if (CredentialFormat.DC_SD_JWT.getFormat().equals(formatLower)) {
            return FormatType.DC_SD_JWT;
        }
        if (CredentialFormat.VC_SD_JWT.getFormat().equals(formatLower)) {
            return FormatType.VC_SD_JWT;
        }
        if ("mso_mdoc".equalsIgnoreCase(formatLower)) {
            return FormatType.MSO_MDOC;
        }
        throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Unsupported credential format: " + format);
    }

    /**
     * Stores presentation record in the database
     * Uses @Transactional to ensure atomicity of database operations
     */
    private void storePresentationRecord(String walletId, String presentationId, SubmitPresentationRequestDTO request, VerifiablePresentationSessionData sessionData, boolean success, LocalDateTime requestedAt) {
        log.debug("Storing presentation record in database - success: {}", success);

        try {
            if (sessionData == null) {
                log.warn("Session data is null for presentationId: {}", presentationId);
                return;
            }

            // Extract verifier information from OpenID4VP object
            String verifierId = extractVerifierId(sessionData);
            String authRequest = extractVerifierAuthRequest(sessionData);
            String presentationData = createPresentationData(request);

            // Create the presentation record
            VerifiablePresentation presentation = VerifiablePresentation.builder().id(presentationId).walletId(walletId).authRequest(authRequest).presentationData(presentationData).verifierId(verifierId).status(success ? OpenID4VPConstants.STATUS_SUCCESS : OpenID4VPConstants.STATUS_ERROR).requestedAt(requestedAt).consent(true).build();

            // Save to database
            verifiablePresentationsRepository.save(presentation);

            log.info("Presentation record stored successfully - recordId: {}, walletId: {}, presentationId: {}, status: {}", presentationId, walletId, presentationId, success ? OpenID4VPConstants.STATUS_SUCCESS : OpenID4VPConstants.STATUS_ERROR);

        } catch (Exception e) {
            log.error("CRITICAL: Failed to store presentation record - walletId: {}, presentationId: {}, verifierId: {}, success: {}", walletId, presentationId, sessionData != null ? extractVerifierId(sessionData) : "unknown", success, e);
        }
    }

    /**
     * Extracts verifier ID from session data
     */
    private String extractVerifierId(VerifiablePresentationSessionData sessionData) {
        try {
            // Since authorizationRequest is a URL, we need to extract client_id from URL parameters
            if (sessionData.getAuthorizationRequest() != null) {
                String authRequestUrl = sessionData.getAuthorizationRequest();
                return UrlParameterUtils.extractQueryParameter(authRequestUrl, OpenID4VPConstants.CLIENT_ID_PARAM);
            }
        } catch (Exception e) {
            log.warn("Failed to extract verifier ID", e);
        }
        return UNKNOWN_VERIFIER;
    }

    /**
     * Extracts verifier authorization request as JSON
     */
    private String extractVerifierAuthRequest(VerifiablePresentationSessionData sessionData) {
        try {
            if (sessionData.getAuthorizationRequest() != null) {
                // Convert the URL string to a JSON object
                Map<String, Object> authRequestData = new HashMap<>();
                authRequestData.put(OpenID4VPConstants.AUTHORIZATION_REQUEST_URL, sessionData.getAuthorizationRequest());
                return objectMapper.writeValueAsString(authRequestData);
            }
        } catch (Exception e) {
            log.warn("Failed to extract verifier auth request", e);
        }
        return EMPTY_JSON;
    }

    /**
     * Creates presentation data JSON with selected credentials and metadata
     */
    private String createPresentationData(SubmitPresentationRequestDTO request) {
        try {
            Map<String, Object> presentationData = new HashMap<>();
            presentationData.put(OpenID4VPConstants.SELECTED_CREDENTIALS, request.getSelectedCredentials());
            if (request.getSelectedCredentialMappings() != null) {
                presentationData.put("selectedCredentialMappings", request.getSelectedCredentialMappings());
            }

            return objectMapper.writeValueAsString(presentationData);
        } catch (Exception e) {
            log.warn("Failed to create presentation data", e);
            return EMPTY_JSON;
        }
    }

    /**
     * Validates all input parameters for presentation submission
     */
    private void validateInputs(SubmitPresentationRequestDTO request) {

        if (request == null) {
            log.error("Request cannot be null");
            throw new IllegalArgumentException("Request cannot be null");
        }

        boolean hasDraft23Selection = request.getSelectedCredentials() != null && !request.getSelectedCredentials().isEmpty();
        boolean hasV1Selection = request.getSelectedCredentialMappings() != null && !request.getSelectedCredentialMappings().isEmpty();
        if (!hasDraft23Selection && !hasV1Selection) {
            log.error("Selected credentials cannot be null or empty");
            throw new IllegalArgumentException("Selected credentials cannot be null or empty");
        }

        log.debug("Input validation passed for request: {}", request);
    }
}

