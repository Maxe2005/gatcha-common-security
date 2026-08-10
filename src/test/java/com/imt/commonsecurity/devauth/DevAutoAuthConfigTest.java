package com.imt.commonsecurity.devauth;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;

/**
 * Verrou de régression AD-8 : le filtre dev-only ne doit jamais pouvoir s'activer hors du profil
 * Spring explicite {@code dev-local} (jamais via une variable d'environnement lisible en prod).
 * Ce test échoue si quelqu'un retire l'annotation {@code @Profile} de {@link DevAutoAuthConfig}.
 */
class DevAutoAuthConfigTest {

    @Test
    void configClass_isGatedByExplicitDevLocalSpringProfile() {
        Profile profile = DevAutoAuthConfig.class.getAnnotation(Profile.class);

        assertThat(profile).isNotNull();
        assertThat(profile.value()).containsExactly("dev-local");
    }

    @Test
    void devAutoAuthFilter_runsAtHighestPrecedence_andCoversAllPaths() {
        DevAutoAuthConfig config = new DevAutoAuthConfig();
        DevTokenClient devTokenClient = config.devTokenClient("http://dev-token-provider", "9876", 500, 1000);

        FilterRegistrationBean<DevAutoAuthFilter> registration = config.devAutoAuthFilter(devTokenClient);

        assertThat(registration.getOrder()).isEqualTo(Ordered.HIGHEST_PRECEDENCE);
        assertThat(registration.getUrlPatterns()).containsExactly("/*");
        assertThat(registration.getFilter()).isNotNull();
    }
}
