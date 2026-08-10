package com.imt.commonsecurity.devauth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

/**
 * Câblage du filtre dev-only (Story 1.1 / AD-8). N'existe dans le contexte Spring QUE lorsque le
 * profil explicite {@code dev-local} est actif — {@code gatcha-common-security} n'a aucune
 * auto-configuration ni component-scan cross-package : un service consommateur doit importer
 * explicitement cette classe (ex. {@code @Import(DevAutoAuthConfig.class)} sur sa classe
 * {@code @SpringBootApplication}) pour que le filtre existe. Voir le README de ce module.
 */
@Configuration
@Profile("dev-local")
public class DevAutoAuthConfig {

    @Bean
    public DevTokenClient devTokenClient(
            @Value("${gatcha.dev-token-provider.host}") String devTokenProviderHost,
            @Value("${gatcha.dev-token-provider.port}") String devTokenProviderPort,
            @Value("${gatcha.dev-token-provider.connect-timeout-ms:500}") int connectTimeoutMs,
            @Value("${gatcha.dev-token-provider.read-timeout-ms:1000}") int readTimeoutMs) {
        // RestTemplate dédié construit ici, jamais publié comme @Bean à part : un service
        // consommateur peut déjà exposer son propre bean RestTemplate (ex. API_joueur, pour
        // TokenVerificationClient) — publier un second bean du même type forcerait une résolution
        // par nom de paramètre fragile (dépend du flag compilateur -parameters, absent ici). Timeouts
        // courts et dédiés (distincts de ceux vers API_authentification, AD-11) : le sidecar est sur
        // le même réseau docker local, une lenteur ici doit se traiter comme une indisponibilité
        // rapide plutôt que de retarder la requête entrante réelle.
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(connectTimeoutMs);
        factory.setReadTimeout(readTimeoutMs);
        return new DevTokenClient(new RestTemplate(factory), devTokenProviderHost, devTokenProviderPort);
    }

    @Bean
    public FilterRegistrationBean<DevAutoAuthFilter> devAutoAuthFilter(DevTokenClient devTokenClient) {
        FilterRegistrationBean<DevAutoAuthFilter> registration =
                new FilterRegistrationBean<>(new DevAutoAuthFilter(devTokenClient));
        // Précédence la plus haute : garantit l'exécution avant tout HandlerInterceptor
        // (AbstractAuthInterceptor inclus), conformément à la contrainte de position d'AD-8.
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        registration.addUrlPatterns("/*");
        return registration;
    }
}
