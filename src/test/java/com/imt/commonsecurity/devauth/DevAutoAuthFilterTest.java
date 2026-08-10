package com.imt.commonsecurity.devauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Le filtre ne doit jamais appeler {@code TokenVerificationClient.verify()} ni poser d'attribut
 * d'identité lui-même (AD-7/AD-8, F2 de la revue adversariale) — ces tests ne vérifient donc que
 * l'ajout (ou non) du header {@code Authorization} avant de continuer la chaîne, jamais une
 * décision d'autorisation.
 */
@ExtendWith(MockitoExtension.class)
class DevAutoAuthFilterTest {

    @Mock
    private DevTokenClient devTokenClient;

    @Test
    void missingAuthorizationHeader_sidecarHasToken_attachesBearerHeaderAndContinuesChain() throws Exception {
        when(devTokenClient.fetchToken()).thenReturn(Optional.of("dev-token-1"));
        DevAutoAuthFilter filter = new DevAutoAuthFilter(devTokenClient);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/players/Sacha");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isNotNull();
        String forwardedHeader = ((jakarta.servlet.http.HttpServletRequest) chain.getRequest()).getHeader("Authorization");
        assertThat(forwardedHeader).isEqualTo("Bearer dev-token-1");
    }

    @Test
    void missingAuthorizationHeader_sidecarUnavailable_passesRequestThroughUnchanged() throws Exception {
        when(devTokenClient.fetchToken()).thenReturn(Optional.empty());
        DevAutoAuthFilter filter = new DevAutoAuthFilter(devTokenClient);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/players/Sacha");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        String forwardedHeader = ((jakarta.servlet.http.HttpServletRequest) chain.getRequest()).getHeader("Authorization");
        assertThat(forwardedHeader).isNull();
    }

    @Test
    void authorizationHeaderAlreadyPresent_neverOverwritten_devTokenClientNeverCalled() throws Exception {
        DevAutoAuthFilter filter = new DevAutoAuthFilter(devTokenClient);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/players/Sacha");
        request.addHeader("Authorization", "Bearer real-user-token");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        String forwardedHeader = ((jakarta.servlet.http.HttpServletRequest) chain.getRequest()).getHeader("Authorization");
        assertThat(forwardedHeader).isEqualTo("Bearer real-user-token");
        verify(devTokenClient, never()).fetchToken();
    }

    @Test
    void blankAuthorizationHeader_treatedAsPresentLikeAbstractAuthInterceptor_neverOverwritten() throws Exception {
        // AbstractAuthInterceptor.preHandle() ne rejette que sur header null/vide (isEmpty()) : un
        // header non-null composé uniquement d'espaces y est traité comme "présent" (et rejeté en
        // aval pour format invalide). Ce filtre doit appliquer exactement la même définition, sinon
        // il écraserait silencieusement un header que l'interceptor considère déjà présent
        // (Review Story 1.1 — AC #2 / Task 3(d)).
        DevAutoAuthFilter filter = new DevAutoAuthFilter(devTokenClient);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/players/Sacha");
        request.addHeader("Authorization", "   ");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        String forwardedHeader = ((jakarta.servlet.http.HttpServletRequest) chain.getRequest()).getHeader("Authorization");
        assertThat(forwardedHeader).isEqualTo("   ");
        verify(devTokenClient, never()).fetchToken();
    }
}
