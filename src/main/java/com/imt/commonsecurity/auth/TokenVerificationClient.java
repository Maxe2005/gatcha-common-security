package com.imt.commonsecurity.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Vérifie un token auprès du endpoint {@code POST /user/verify-token} d'API_authentification —
 * même contrat que celui utilisé par tous les services Java du Gatcha.
 */
public class TokenVerificationClient {

    private static final Logger log = LoggerFactory.getLogger(TokenVerificationClient.class);
    private static final String VERIFY_TOKEN_ENDPOINT = "/user/verify-token";
    private static final String X_REQUEST_ID = "X-Request-Id";

    private final RestTemplate restTemplate;
    private final String authApiBaseUrl;

    public TokenVerificationClient(RestTemplate restTemplate, String authApiHost, String authApiPort) {
        this.restTemplate = restTemplate;
        this.authApiBaseUrl = authApiHost + ":" + authApiPort;
    }

    public TokenVerificationResult verify(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        String requestId = extractRequestId();
        if (requestId != null) {
            headers.add(X_REQUEST_ID, requestId);
        }
        HttpEntity<AuthTokenRequest> entity = new HttpEntity<>(new AuthTokenRequest(token), headers);

        try {
            ResponseEntity<AuthTokenResponse> response = restTemplate.postForEntity(
                    authApiBaseUrl + VERIFY_TOKEN_ENDPOINT, entity, AuthTokenResponse.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                return new TokenVerificationResult.Valid(response.getBody().user(), response.getBody().role());
            }
            return new TokenVerificationResult.Rejected("Token invalide ou expiré");
        } catch (HttpClientErrorException e) {
            log.warn("Refus Auth (401/403) : {}", e.getMessage());
            return new TokenVerificationResult.Rejected("Token invalide ou expiré");
        } catch (HttpServerErrorException e) {
            log.error("Crash API Auth (500) lors de la vérification du token : {}", e.getMessage());
            // Fail-safe : on considère le token invalide plutôt que de bloquer en 500
            return new TokenVerificationResult.Rejected("Token invalide (Erreur serveur distant)");
        } catch (Exception e) {
            log.error("Service Auth injoignable : {}", e.getMessage());
            return new TokenVerificationResult.Unreachable("Service d'authentification indisponible");
        }
    }

    /**
     * Extrait l'identifiant de correlation X-Request-Id à forwarder sur l'appel {@code
     * verify-token} : en priorité le header de la requête entrante (via {@code
     * RequestContextHolder}), en repli le MDC (posé par les AuthInterceptors des consommateurs).
     * Sans forwarding, API_authentification ne reçoit jamais l'ID et ne peut pas loguer la
     * corrélation de bout en bout (story 2.1).
     */
    private String extractRequestId() {
        ServletRequestAttributes attributes =
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes != null) {
            String requestId = attributes.getRequest().getHeader(X_REQUEST_ID);
            if (requestId != null) {
                return requestId;
            }
        }
        return MDC.get(X_REQUEST_ID);
    }
}
