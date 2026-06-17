package io.mosip.mimoto.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.constant.OpenID4VPConstants;
import io.mosip.mimoto.constant.SigningAlgorithm;
import io.mosip.mimoto.dto.DecryptedCredentialDTO;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.SelectedCredentials;
import io.mosip.mimoto.dto.SubmitPresentationRequestDTO;
import io.mosip.mimoto.dto.SubmitPresentationResponseDTO;
import io.mosip.mimoto.dto.VPResponseDTO;
import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.model.VerifiablePresentation;
import io.mosip.mimoto.repository.VerifiablePresentationsRepository;
import io.mosip.mimoto.service.impl.OpenID4VPService;
import io.mosip.mimoto.service.impl.WalletPresentationServiceImpl;
import io.mosip.mimoto.util.SigningKeyUtil;
import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest;
import io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadata;
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken;
import io.mosip.openID4VP.constants.FormatType;
import io.mosip.openID4VP.verifier.VerifierResponse;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.ResponseEntity;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static io.mosip.mimoto.exception.ErrorConstants.INVALID_REQUEST;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class WalletPresentationServiceTest {

    @Mock
    private VerifierService verifierService;

    @Mock
    private OpenID4VPService openID4VPService;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private KeyPairRetrievalService keyPairService;

    @Mock
    private CredentialMatchingService credentialMatchingService;

    @Mock
    private VerifiablePresentationsRepository verifiablePresentationsRepository;

    @Mock
    private DataProtectionService dataProtectionService;

    @InjectMocks
    private WalletPresentationServiceImpl walletPresentationService;

    private String walletId;
    private String presentationId;
    private String urlEncodedVPAuthorizationRequest;
    private String base64Key;
    private VerifiersDTO verifiersDTO;
    private AuthorizationDcqlRequest authorizationRequest;
    private OpenID4VP mockOpenID4VP;
    private VerifiablePresentationSessionData sessionData;
    private SubmitPresentationRequestDTO submitRequest;
    private JWK jwk;
    private JWSSigner jwsSigner;

    @Before
    public void setUp() throws Exception {
        walletId = "wallet-123";
        presentationId = "presentation-456";
        base64Key = "base64-encoded-key";
        urlEncodedVPAuthorizationRequest = "client_id=test-client&response_type=vp_token";

        VerifierDTO verifierDTO = new VerifierDTO(
                "test-client",
                List.of("https://verifier.com/response"),
                List.of("https://verifier.com/jwks"),
                null,
                false
        );
        verifiersDTO = new VerifiersDTO();
        verifiersDTO.setVerifiers(List.of(verifierDTO));

        mockOpenID4VP = mock(OpenID4VP.class);
        authorizationRequest = mock(AuthorizationDcqlRequest.class);
        when(authorizationRequest.getClientId()).thenReturn("test-client");
        when(authorizationRequest.getRedirectUri()).thenReturn("https://verifier.com/redirect");

        ClientMetadata clientMetadata = mock(ClientMetadata.class);
        when(clientMetadata.getClientName()).thenReturn("Test Verifier");
        when(clientMetadata.getLogoUri()).thenReturn("https://verifier.com/logo.png");
        when(authorizationRequest.getClientMetadata()).thenReturn(clientMetadata);

        VCCredentialResponse vcCredentialResponse = new VCCredentialResponse();
        vcCredentialResponse.setFormat(CredentialFormat.LDP_VC.getFormat());
        vcCredentialResponse.setCredential(Map.of("credentialSubject", Map.of("id", "did:jwk:abc#0")));

        DecryptedCredentialDTO credentialDTO = DecryptedCredentialDTO.builder()
                .id("cred-123")
                .walletId(walletId)
                .credential(vcCredentialResponse)
                .build();

        sessionData = new VerifiablePresentationSessionData();
        sessionData.setPresentationId(presentationId);
        sessionData.setAuthorizationRequest(urlEncodedVPAuthorizationRequest);
        sessionData.setCreatedAt(Instant.now());
        sessionData.setVerifierClientPreregistered(true);
        sessionData.setMatchingCredentials(List.of(credentialDTO));

        submitRequest = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(SelectedCredentials.ofStrings(List.of("cred-123")))
                .build();

        jwk = mock(JWK.class);
        jwsSigner = mock(JWSSigner.class);
    }

    @Test
    public void testHandleVPAuthorizationRequestSuccess() throws Exception {
        when(openID4VPService.getPreRegisteredVerifiers()).thenReturn(List.of());
        when(openID4VPService.create(anyString(), anyList(), anyBoolean())).thenReturn(mockOpenID4VP);
        when(verifierService.isVerifierClientPreregistered(anyList(), anyString())).thenReturn(true);
        when(verifierService.isVerifierTrustedByWallet(anyString(), anyString())).thenReturn(true);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(authorizationRequest);

        VPResponseDTO result = walletPresentationService.handleVPAuthorizationRequest(urlEncodedVPAuthorizationRequest, walletId);

        assertNotNull(result);
        assertEquals("test-client", result.getVerifiablePresentationVerifierDTO().getId());
        assertEquals("Test Verifier", result.getVerifiablePresentationVerifierDTO().getName());
        verify(openID4VPService).create(anyString(), anyList(), anyBoolean());
    }

    @Test
    public void testHandlePresentationActionInvalidRequestReturns400() {
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder().build();

        ResponseEntity<?> response = walletPresentationService.handlePresentationAction(
                walletId, presentationId, request, sessionData, base64Key
        );

        assertNotNull(response);
        assertEquals(400, response.getStatusCode().value());
    }

    @Test
    public void testHandlePresentationSubmissionNullWalletKeyReturns400() {
        ResponseEntity<?> response = walletPresentationService.handlePresentationAction(
                walletId, presentationId, submitRequest, sessionData, null
        );

        assertNotNull(response);
        assertEquals(400, response.getStatusCode().value());
        ErrorDTO error = (ErrorDTO) response.getBody();
        assertNotNull(error);
        assertEquals(INVALID_REQUEST.getErrorCode(), error.getErrorCode());
    }

    @Test
    public void testSubmitPresentationSuccess() throws Exception {
        when(openID4VPService.getPreRegisteredVerifiers()).thenReturn(List.of());
        when(openID4VPService.create(anyString(), anyList(), anyBoolean())).thenReturn(mockOpenID4VP);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(mock(java.security.KeyPair.class));
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(authorizationRequest);

        UnsignedVPToken unsignedVPToken = mock(UnsignedVPToken.class);
        when(unsignedVPToken.getFormat()).thenReturn(FormatType.LDP_VC);
        when(unsignedVPToken.getDataToSign()).thenReturn("base64-encoded-data".getBytes());
        when(mockOpenID4VP.constructUnsignedVPToken(anyMap())).thenReturn(List.of(unsignedVPToken));

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getStatusCode()).thenReturn(200);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/success");
        when(mockOpenID4VP.sendVPResponseToVerifier(anyList())).thenReturn(verifierResponse);

        try (MockedStatic<SigningKeyUtil> signingKeyUtil = mockStatic(SigningKeyUtil.class)) {
            signingKeyUtil.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            signingKeyUtil.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));

            SubmitPresentationResponseDTO result = walletPresentationService.submitPresentation(
                    sessionData, walletId, presentationId, submitRequest, base64Key
            );

            assertNotNull(result);
            assertEquals(OpenID4VPConstants.STATUS_SUCCESS, result.getStatus());
            verify(verifiablePresentationsRepository).save(any(VerifiablePresentation.class));
        }
    }

    @Test
    public void testSubmitPresentationShareFailureReturnsErrorStatus() throws Exception {
        when(openID4VPService.getPreRegisteredVerifiers()).thenReturn(List.of());
        when(openID4VPService.create(anyString(), anyList(), anyBoolean())).thenReturn(mockOpenID4VP);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(mock(java.security.KeyPair.class));
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(authorizationRequest);

        UnsignedVPToken unsignedVPToken = mock(UnsignedVPToken.class);
        when(unsignedVPToken.getFormat()).thenReturn(FormatType.LDP_VC);
        when(unsignedVPToken.getDataToSign()).thenReturn("base64-encoded-data".getBytes());
        when(mockOpenID4VP.constructUnsignedVPToken(anyMap())).thenReturn(List.of(unsignedVPToken));

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getStatusCode()).thenReturn(500);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/error");
        when(mockOpenID4VP.sendVPResponseToVerifier(anyList())).thenReturn(verifierResponse);

        try (MockedStatic<SigningKeyUtil> signingKeyUtil = mockStatic(SigningKeyUtil.class)) {
            signingKeyUtil.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            signingKeyUtil.when(() -> SigningKeyUtil.createSigner(any(), any())).thenReturn(jwsSigner);

            when(jwsSigner.sign(any(JWSHeader.class), any(byte[].class))).thenReturn(Base64URL.encode("signature"));

            SubmitPresentationResponseDTO result = walletPresentationService.submitPresentation(
                    sessionData, walletId, presentationId, submitRequest, base64Key
            );

            assertNotNull(result);
            assertEquals(OpenID4VPConstants.STATUS_ERROR, result.getStatus());
        }
    }

    @Test
    public void testHandlePresentationActionRejectionSuccess() throws Exception {
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .errorCode("access_denied")
                .errorMessage("User denied access")
                .build();

        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(verifierResponse.getRedirectUri()).thenReturn("https://verifier.com/rejected");
        when(openID4VPService.sendErrorToVerifier(any(), any(ErrorDTO.class))).thenReturn(verifierResponse);

        ResponseEntity<?> response = walletPresentationService.handlePresentationAction(
                walletId, presentationId, request, sessionData, base64Key
        );

        assertNotNull(response);
        assertEquals(200, response.getStatusCode().value());
        verify(openID4VPService).sendErrorToVerifier(any(), any(ErrorDTO.class));
    }

    @Test
    public void testHandlePresentationActionJoseErrorReturns500() throws Exception {
        when(openID4VPService.getPreRegisteredVerifiers()).thenReturn(List.of());
        when(openID4VPService.create(anyString(), anyList(), anyBoolean())).thenReturn(mockOpenID4VP);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class))).thenReturn(mock(java.security.KeyPair.class));
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(authorizationRequest);
        // Return one token so signLdpVcToken is actually invoked and the JOSEException can fire.
        // getDataToSign() is NOT stubbed because createSigner throws before it is ever called.
        UnsignedVPToken unsignedTokenForJoseTest = mock(UnsignedVPToken.class);
        when(unsignedTokenForJoseTest.getFormat()).thenReturn(FormatType.LDP_VC);
        when(unsignedTokenForJoseTest.getSignatureAlgorithm()).thenReturn(null);
        when(mockOpenID4VP.constructUnsignedVPToken(anyMap())).thenReturn(List.of(unsignedTokenForJoseTest));

        try (MockedStatic<SigningKeyUtil> signingKeyUtil = mockStatic(SigningKeyUtil.class)) {
            signingKeyUtil.when(() -> SigningKeyUtil.generateJwk(any(), any())).thenReturn(jwk);
            signingKeyUtil.when(() -> SigningKeyUtil.createSigner(any(), any())).thenThrow(new JOSEException("JWT signing error"));

            ResponseEntity<?> response = walletPresentationService.handlePresentationAction(
                    walletId, presentationId, submitRequest, sessionData, base64Key
            );

            assertNotNull(response);
            assertEquals(500, response.getStatusCode().value());
        }
    }
}
