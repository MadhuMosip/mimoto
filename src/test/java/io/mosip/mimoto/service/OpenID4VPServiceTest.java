package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.impl.OpenID4VPService;
import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest;
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest;
import io.mosip.openID4VP.dcql.query.DCQLQuery;
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition;
import io.mosip.openID4VP.common.OpenID4VPErrorCodes;
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions;
import io.mosip.openID4VP.verifier.VerifierResponse;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;
import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class OpenID4VPServiceTest {

    @Mock
    private VerifierService verifierService;

    @InjectMocks
    private OpenID4VPService openID4VPService;

    private VerifiersDTO verifiersDTO;

    @Before
    public void setUp() {
        VerifierDTO verifierDTO = VerifierDTO.builder()
                .clientId("test-client-id")
                .responseUris(List.of("https://example.com/response"))
                .jwksUri("https://example.com/.well-known/jwks.json")
                .allowUnsignedRequest(true)
                .build();
        verifiersDTO = VerifiersDTO.builder().verifiers(List.of(verifierDTO)).build();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // create()
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    public void create_withPresentationIdOnly_returnsOpenID4VP() {
        OpenID4VP result = openID4VPService.create("presentation-123");
        assertNotNull(result);
    }

    @Test
    public void create_withTrustedVerifiers_returnsOpenID4VP() {
        OpenID4VP result = openID4VPService.create("presentation-123", List.of());
        assertNotNull(result);
    }

    @Test
    public void create_withValidateFlag_returnsOpenID4VP() {
        OpenID4VP result = openID4VPService.create("presentation-123", List.of(), false);
        assertNotNull(result);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // resolvePresentationDefinition()  — Draft-23 path
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    public void resolvePresentationDefinition_withValidDraft23Request_returnsPresentationDefinition() throws Exception {
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);

        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        AuthorizationPresentationExchangeRequest peRequest =
                mock(AuthorizationPresentationExchangeRequest.class);
        PresentationDefinition presentationDefinition = mock(PresentationDefinition.class);
        when(peRequest.getPresentationDefinition()).thenReturn(presentationDefinition);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(peRequest);

        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString(), anyList(), anyBoolean());

        PresentationDefinition result = spyService.resolvePresentationDefinition(
                "presentation-123", "auth-request", true);

        assertNotNull(result);
        assertEquals(presentationDefinition, result);
    }

    @Test
    public void resolvePresentationDefinition_withDcqlRequest_returnsNull() throws Exception {
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);

        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        AuthorizationDcqlRequest dcqlRequest = mock(AuthorizationDcqlRequest.class);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(dcqlRequest);

        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString(), anyList(), anyBoolean());

        PresentationDefinition result = spyService.resolvePresentationDefinition(
                "presentation-123", "auth-request", true);

        assertNull(result);
    }

    @Test
    public void resolvePresentationDefinition_withNullInputs_returnsNull() throws Exception {
        assertNull(openID4VPService.resolvePresentationDefinition(null, "auth-request", true));
        assertNull(openID4VPService.resolvePresentationDefinition("presentation-123", null, true));
        verifyNoInteractions(verifierService);
    }

    @Test(expected = ApiNotAccessibleException.class)
    public void resolvePresentationDefinition_whenVerifierServiceFails_propagatesException() throws Exception {
        when(verifierService.getTrustedVerifiers()).thenThrow(new ApiNotAccessibleException());
        openID4VPService.resolvePresentationDefinition("presentation-123", "auth-request", true);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // resolveDcqlQuery()  — OVP 1.0 path
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    public void resolveDcqlQuery_withValidOvp10Request_returnsDcqlQuery() throws Exception {
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);

        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        AuthorizationDcqlRequest dcqlRequest = mock(AuthorizationDcqlRequest.class);
        DCQLQuery dcqlQuery = mock(DCQLQuery.class);
        when(dcqlRequest.getDcqlQuery()).thenReturn(dcqlQuery);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(dcqlRequest);

        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString(), anyList(), anyBoolean());

        DCQLQuery result = spyService.resolveDcqlQuery("presentation-123", "auth-request", true);

        assertNotNull(result);
        assertEquals(dcqlQuery, result);
    }

    @Test
    public void resolveDcqlQuery_withDraft23Request_returnsNull() throws Exception {
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);

        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        AuthorizationPresentationExchangeRequest peRequest =
                mock(AuthorizationPresentationExchangeRequest.class);
        when(mockOpenID4VP.authenticateVerifier(anyString())).thenReturn(peRequest);

        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString(), anyList(), anyBoolean());

        DCQLQuery result = spyService.resolveDcqlQuery("presentation-123", "auth-request", true);

        assertNull(result);
    }

    @Test
    public void resolveDcqlQuery_withNullInputs_returnsNull() throws Exception {
        assertNull(openID4VPService.resolveDcqlQuery(null, "auth-request", true));
        assertNull(openID4VPService.resolveDcqlQuery("presentation-123", null, true));
        verifyNoInteractions(verifierService);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // sendErrorToVerifier()
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    public void sendErrorToVerifier_withAccessDenied_sendsCorrectException() throws Exception {
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);

        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifierResponse verifierResponse = mock(VerifierResponse.class);
        when(mockOpenID4VP.authenticateVerifier(anyString()))
                .thenReturn(mock(AuthorizationPresentationExchangeRequest.class));
        when(mockOpenID4VP.sendErrorInfoToVerifier(any())).thenReturn(verifierResponse);

        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString(), anyList(), anyBoolean());

        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData();
        sessionData.setPresentationId("presentation-123");
        sessionData.setAuthorizationRequest("auth-request");
        sessionData.setVerifierClientPreregistered(true);

        ErrorDTO payload = new ErrorDTO();
        payload.setErrorCode(OpenID4VPErrorCodes.ACCESS_DENIED);
        payload.setErrorMessage("user denied");

        VerifierResponse result = spyService.sendErrorToVerifier(sessionData, payload);

        assertEquals(verifierResponse, result);
        ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
        verify(mockOpenID4VP).sendErrorInfoToVerifier(captor.capture());
        assertTrue(captor.getValue() instanceof OpenID4VPExceptions.AccessDenied);
    }

    @Test
    public void sendErrorToVerifier_withInvalidTransactionData_sendsCorrectException() throws Exception {
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);

        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        when(mockOpenID4VP.authenticateVerifier(anyString()))
                .thenReturn(mock(AuthorizationPresentationExchangeRequest.class));
        when(mockOpenID4VP.sendErrorInfoToVerifier(any())).thenReturn(mock(VerifierResponse.class));

        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString(), anyList(), anyBoolean());

        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData();
        sessionData.setPresentationId("presentation-123");
        sessionData.setAuthorizationRequest("auth-request");
        sessionData.setVerifierClientPreregistered(true);

        ErrorDTO payload = new ErrorDTO();
        payload.setErrorCode(OpenID4VPErrorCodes.INVALID_TRANSACTION_DATA);
        payload.setErrorMessage("missing claims");

        spyService.sendErrorToVerifier(sessionData, payload);

        ArgumentCaptor<Exception> captor = ArgumentCaptor.forClass(Exception.class);
        verify(mockOpenID4VP).sendErrorInfoToVerifier(captor.capture());
        assertTrue(captor.getValue() instanceof OpenID4VPExceptions.InvalidTransactionData);
    }

    @Test(expected = IllegalArgumentException.class)
    public void sendErrorToVerifier_withNullSession_throwsIllegalArgument() throws Exception {
        ErrorDTO payload = new ErrorDTO();
        payload.setErrorCode(OpenID4VPErrorCodes.ACCESS_DENIED);
        openID4VPService.sendErrorToVerifier(null, payload);
    }

    @Test(expected = IllegalArgumentException.class)
    public void sendErrorToVerifier_withNullPresentationId_throwsIllegalArgument() throws Exception {
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData();
        sessionData.setPresentationId(null);
        sessionData.setAuthorizationRequest("auth-request");
        ErrorDTO payload = new ErrorDTO();
        payload.setErrorCode(OpenID4VPErrorCodes.ACCESS_DENIED);
        openID4VPService.sendErrorToVerifier(sessionData, payload);
    }

    @Test(expected = IOException.class)
    public void sendErrorToVerifier_whenVerifierServiceThrows_propagatesIOException() throws Exception {
        when(verifierService.getTrustedVerifiers()).thenThrow(new IOException("network error"));
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData();
        sessionData.setPresentationId("presentation-123");
        sessionData.setAuthorizationRequest("auth-request");
        sessionData.setVerifierClientPreregistered(false);
        ErrorDTO payload = new ErrorDTO();
        payload.setErrorCode(OpenID4VPErrorCodes.ACCESS_DENIED);
        openID4VPService.sendErrorToVerifier(sessionData, payload);
    }
}
