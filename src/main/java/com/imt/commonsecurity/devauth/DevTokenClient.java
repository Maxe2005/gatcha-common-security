package com.imt.commonsecurity.devauth;

import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

/**
 * Interroge le sidecar dev-token-provider (Story 1.1 / AD-8) pour récupérer le token dev courant.
 * Utilisé exclusivement par {@link DevAutoAuthFilter} — ce client ne vérifie rien et n'est jamais
 * un substitut à {@link com.imt.commonsecurity.auth.TokenVerificationClient} : il ne fait que
 * proposer un token à attacher en amont de la vérification réelle, qui reste entière.
 */
public class DevTokenClient {

    private static final Logger log = LoggerFactory.getLogger(DevTokenClient.class);
    private static final String TOKEN_ENDPOINT = "/token";

    private final RestTemplate restTemplate;
    private final String baseUrl;

    public DevTokenClient(RestTemplate restTemplate, String devTokenProviderHost, String devTokenProviderPort) {
        this.restTemplate = restTemplate;
        this.baseUrl = devTokenProviderHost + ":" + devTokenProviderPort;
    }

    /**
     * Récupère le token courant, ou {@link Optional#empty()} si le sidecar est injoignable, en
     * erreur, ou n'a encore aucun token disponible. Ne propage jamais d'exception : l'appelant
     * ({@link DevAutoAuthFilter}) doit toujours pouvoir se comporter comme si le token dev était
     * simplement indisponible, jamais planter la requête entrante.
     */
    public Optional<String> fetchToken() {
        try {
            ResponseEntity<DevTokenResponse> response =
                    restTemplate.getForEntity(baseUrl + TOKEN_ENDPOINT, DevTokenResponse.class);
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                return Optional.ofNullable(response.getBody().token());
            }
            return Optional.empty();
        } catch (Exception e) {
            log.debug("[dev-auto-auth] Sidecar dev-token-provider indisponible : {}", e.getMessage());
            return Optional.empty();
        }
    }
}
