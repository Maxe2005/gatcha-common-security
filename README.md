# gatcha-common-security

Vérification de token partagée entre les microservices Java du Gatcha (`API_monstres`, `API_joueur`, à terme `API_invocations`). Factorise le seul appel réellement identique entre leurs `AuthInterceptor` : `POST {authApiHost}:{authApiPort}/user/verify-token` auprès d'`API_authentification`, avec la même gestion d'erreurs (4xx → rejeté, 5xx → rejeté en fail-safe, injoignable → 500).

Volontairement **hors périmètre** : l'extraction du token (chaque service décide s'il accepte un fallback cookie ou non) et toute politique d'autorisation au-delà de l'authentification (ex: "un joueur ne modifie que son propre profil").

## Intégration

1. Dépendance Maven (voir la racine du repo `GatchaApi` pour comment ce module est construit et installé avant le build du service consommateur — pas de registre Maven publié) :
   ```xml
   <dependency>
       <groupId>com.imt</groupId>
       <artifactId>gatcha-common-security</artifactId>
       <version>0.1.0</version>
   </dependency>
   ```
2. Déclarer un `TokenVerificationClient` (host/port d'API_authentification, `RestTemplate`) et un `@Component` qui étend `AbstractAuthInterceptor` :
   ```java
   @Component
   public class AuthInterceptor extends AbstractAuthInterceptor {
       public AuthInterceptor(TokenVerificationClient client) {
           super(client);
       }
   }
   ```
3. Pour ajouter une politique d'autorisation propre au service (ex: self-or-admin), surcharger `postAuthorize(request, response, valid)` — voir `API_joueur`.
4. Enregistrer l'interceptor dans un `WebMvcConfigurer` comme avant (`addInterceptors`), rien ne change côté `WebConfig`.

## Automatisation de l'auth en dev local (Story 1.1 / AD-8)

Un sidecar `dev-token-provider` (racine du repo `GatchaApi`, profil Compose dédié, jamais démarré par défaut) s'authentifie avec un compte seedé et rafraîchit son token proactivement. Le package `devauth` de ce module expose le filtre dev-only qui l'exploite :

- **`DevTokenClient`** — interroge `GET {devTokenProviderHost}:{devTokenProviderPort}/token` pour récupérer le token courant du sidecar. Ne vérifie rien, ne lance jamais d'exception (renvoie `Optional.empty()` si le sidecar est indisponible).
- **`DevAutoAuthFilter`** — un `jakarta.servlet.Filter` (pas un `HandlerInterceptor`) : si la requête n'a pas de header `Authorization`, il en attache un via `DevTokenClient`. Il ne fait **jamais** autre chose : pas d'appel à `TokenVerificationClient.verify()`, pas d'attribut `username`/`role` posé lui-même. Un filtre servlet s'exécute structurellement avant tout `HandlerInterceptor`, ce qui garantit sa position strictement en amont d'`AbstractAuthInterceptor` sans avoir besoin de l'y coupler.
- **`DevAutoAuthConfig`** — `@Configuration` annotée `@Profile("dev-local")` : câble `DevTokenClient` + `FilterRegistrationBean<DevAutoAuthFilter>` (précédence `Ordered.HIGHEST_PRECEDENCE`, `/*`). **N'existe dans le contexte Spring que si le profil `dev-local` est actif** — jamais via une variable d'environnement lisible en prod (AD-8).

### ⚠️ Câblage requis côté consommateur — aucun component-scan cross-package

Ce module n'a **aucune** auto-configuration Spring Boot ni `META-INF/spring.factories`/`AutoConfiguration.imports` : `AbstractAuthInterceptor`, `TokenVerificationClient` et `DevAutoAuthConfig` sont de simples classes, jamais détectées automatiquement par le component-scan d'un service consommateur (racines de package différentes : `com.imt.API_joueur` vs `com.imt.commonsecurity`). Pour activer le filtre dev-only, chaque service doit explicitement importer `DevAutoAuthConfig` sur sa classe `@SpringBootApplication` :

```java
@Import(DevAutoAuthConfig.class) // sans effet tant que le profil "dev-local" n'est pas actif
@SpringBootApplication
public class MonApplication { ... }
```

Et déclarer les propriétés que `DevAutoAuthConfig` attend (host/port du sidecar, timeouts optionnels) :

```properties
gatcha.dev-token-provider.host=${DEV_TOKEN_PROVIDER_HOST:http://dev-token-provider}
gatcha.dev-token-provider.port=${DEV_TOKEN_PROVIDER_PORT:9876}
```

Consommateurs actuels de ce câblage : `API_joueur`, `API_monstres`. `API_invocations` en bénéficiera automatiquement une fois migré vers ce module (Story 1.2) — appliquer le même `@Import` à ce moment-là.

### Non négociable (AD-7/AD-8)

- Le filtre ne doit **jamais** poser une identité de repli ni un token factice si le sidecar est indisponible — laisser la requête inchangée pour qu'`AbstractAuthInterceptor` rejette normalement (fail-closed).
- N'ajouter aucune branche dans `AbstractAuthInterceptor`/`postAuthorize()` qui contournerait `TokenVerificationClient.verify()` selon le profil actif : le seul point d'appel à `verify()` reste `AbstractAuthInterceptor.preHandle()`, non branché.
