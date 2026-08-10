package com.imt.commonsecurity.devauth;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Filtre servlet dev-only (Story 1.1 / AD-8) — n'existe dans le contexte Spring que lorsque le
 * profil explicite {@code dev-local} est actif (voir {@link DevAutoAuthConfig}, jamais via une
 * simple variable d'environnement lisible en prod).
 *
 * <p>Son seul rôle : si la requête entrante n'a pas de header {@code Authorization}, en attacher
 * un obtenu auprès du sidecar {@code dev-token-provider}. Un {@code Filter} servlet s'exécute
 * structurellement avant tout {@code HandlerInterceptor} (garantie du conteneur), donc strictement
 * en amont de {@link com.imt.commonsecurity.auth.AbstractAuthInterceptor} — qu'il ne modifie, ne
 * court-circuite ni n'étend jamais : ce filtre ne pose aucun attribut {@code username}/{@code role}
 * et n'appelle jamais {@code TokenVerificationClient.verify()} lui-même.
 *
 * <p>Si le sidecar est injoignable ou n'a pas encore de token, ce filtre ne fait RIEN — jamais de
 * token ou d'identité de repli fabriqués ici : {@code AbstractAuthInterceptor} reste seul
 * responsable de la vérification réelle et rejette normalement (fail-closed, jamais fail-open,
 * AD-7).
 */
public class DevAutoAuthFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(DevAutoAuthFilter.class);
    private static final String AUTH_HEADER = "Authorization";

    private final DevTokenClient devTokenClient;

    public DevAutoAuthFilter(DevTokenClient devTokenClient) {
        this.devTokenClient = devTokenClient;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest httpRequest)) {
            chain.doFilter(request, response);
            return;
        }

        // Même définition de "header présent" que AbstractAuthInterceptor.preHandle() (isEmpty(),
        // pas isBlank()) : un header non-null même composé uniquement d'espaces doit être laissé
        // intact ici et rejeté normalement en aval, jamais silencieusement écrasé par ce filtre
        // (AC #2 / Task 3(d) — Review Story 1.1).
        String existingHeader = httpRequest.getHeader(AUTH_HEADER);
        if (existingHeader != null && !existingHeader.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }

        Optional<String> devToken = devTokenClient.fetchToken();
        if (devToken.isEmpty()) {
            log.debug("[dev-auto-auth] Aucun token dev disponible — requête inchangée, vérification normale en aval");
            chain.doFilter(request, response);
            return;
        }

        chain.doFilter(new AuthorizationHeaderRequestWrapper(httpRequest, "Bearer " + devToken.get()), response);
    }

    /**
     * Fait apparaître un header {@code Authorization} synthétique — n'est instancié que lorsque ce
     * header est absent/vide (voir {@link #doFilter}). Ne modifie rien d'autre de la requête.
     */
    private static final class AuthorizationHeaderRequestWrapper extends HttpServletRequestWrapper {

        private final String authorizationValue;

        AuthorizationHeaderRequestWrapper(HttpServletRequest request, String authorizationValue) {
            super(request);
            this.authorizationValue = authorizationValue;
        }

        @Override
        public String getHeader(String name) {
            if (AUTH_HEADER.equalsIgnoreCase(name)) {
                return authorizationValue;
            }
            return super.getHeader(name);
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            if (AUTH_HEADER.equalsIgnoreCase(name)) {
                return Collections.enumeration(Collections.singletonList(authorizationValue));
            }
            return super.getHeaders(name);
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            List<String> names = Collections.list(super.getHeaderNames());
            if (names.stream().noneMatch(AUTH_HEADER::equalsIgnoreCase)) {
                names.add(AUTH_HEADER);
            }
            return Collections.enumeration(names);
        }
    }
}
