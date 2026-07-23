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
