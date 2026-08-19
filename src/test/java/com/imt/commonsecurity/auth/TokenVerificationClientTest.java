package com.imt.commonsecurity.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.MDC;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Story 2.1 : le client partagé doit forwarder l'identifiant de correlation X-Request-Id sur
 * l'appel {@code verify-token} — d'abord depuis le header de la requête entrante, puis en repli
 * depuis le MDC — afin qu'API_authentification puisse loguer la corrélation de bout en bout.
 */
class TokenVerificationClientTest {

    private static final String X_REQUEST_ID = "X-Request-Id";
    private static final String AUTH_BASE_URL = "http://api-authentification:8080";
    private static final String VERIFY_ENDPOINT = AUTH_BASE_URL + "/user/verify-token";

    @AfterEach
    void cleanUp() {
        RequestContextHolder.resetRequestAttributes();
        MDC.remove(X_REQUEST_ID);
    }

    @Test
    void verify_forwardsXRequestId_fromCurrentRequestHeader() {
        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.addHeader(X_REQUEST_ID, "correlation-123");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(servletRequest));

        RestTemplate restTemplate = mock(RestTemplate.class);
        when(restTemplate.postForEntity(eq(VERIFY_ENDPOINT), any(), eq(AuthTokenResponse.class)))
                .thenReturn(new ResponseEntity<>(new AuthTokenResponse("alice", "USER"), HttpStatus.OK));

        new TokenVerificationClient(restTemplate, "http://api-authentification", "8080")
                .verify("some-token");

        assertThat(capturedRequestId(restTemplate)).isEqualTo("correlation-123");
    }

    @Test
    void verify_forwardsXRequestId_fromMdcWhenNoRequestContext() {
        MDC.put(X_REQUEST_ID, "mdc-id");

        RestTemplate restTemplate = mock(RestTemplate.class);
        when(restTemplate.postForEntity(eq(VERIFY_ENDPOINT), any(), eq(AuthTokenResponse.class)))
                .thenReturn(new ResponseEntity<>(new AuthTokenResponse("alice", "USER"), HttpStatus.OK));

        new TokenVerificationClient(restTemplate, "http://api-authentification", "8080")
                .verify("some-token");

        assertThat(capturedRequestId(restTemplate)).isEqualTo("mdc-id");
    }

    @Test
    void verify_addsNoXRequestId_whenAbsentFromRequestAndMdc() {
        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(servletRequest));

        RestTemplate restTemplate = mock(RestTemplate.class);
        when(restTemplate.postForEntity(eq(VERIFY_ENDPOINT), any(), eq(AuthTokenResponse.class)))
                .thenReturn(new ResponseEntity<>(new AuthTokenResponse("alice", "USER"), HttpStatus.OK));

        new TokenVerificationClient(restTemplate, "http://api-authentification", "8080")
                .verify("some-token");

        assertThat(capturedRequestId(restTemplate)).isNull();
    }

    private String capturedRequestId(RestTemplate restTemplate) {
        ArgumentCaptor<HttpEntity> entityCaptor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(restTemplate).postForEntity(eq(VERIFY_ENDPOINT), entityCaptor.capture(), eq(AuthTokenResponse.class));
        HttpHeaders headers = entityCaptor.getValue().getHeaders();
        return headers.getFirst(X_REQUEST_ID);
    }
}