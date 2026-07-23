package com.imt.commonsecurity.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

/**
 * Vérifie un token auprès du endpoint {@code POST /user/verify-token} d'API_authentification —
 * même contrat que celui utilisé par tous les services Java du Gatcha.
 */
public class TokenVerificationClient {

    private static final Logger log = LoggerFactory.getLogger(TokenVerificationClient.class);
    private static final String VERIFY_TOKEN_ENDPOINT = "/user/verify-token";

    private final RestTemplate restTemplate;
    private final String authApiBaseUrl;

    public TokenVerificationClient(RestTemplate restTemplate, String authApiHost, String authApiPort) {
        this.restTemplate = restTemplate;
        this.authApiBaseUrl = authApiHost + ":" + authApiPort;
    }

    public TokenVerificationResult verify(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
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
}
