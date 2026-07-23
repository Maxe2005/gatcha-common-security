package com.imt.commonsecurity.auth;

import java.io.IOException;

import org.springframework.http.MediaType;
import org.springframework.web.servlet.HandlerInterceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Vérifie la présence et la validité d'un token {@code Authorization: Bearer} auprès
 * d'API_authentification. Pose les attributs de requête {@code username}/{@code role} une fois le
 * token validé, puis délègue à {@link #postAuthorize} pour toute politique d'autorisation propre
 * au service (ex: un joueur qui ne peut modifier que son propre profil).
 */
public abstract class AbstractAuthInterceptor implements HandlerInterceptor {

    private static final String AUTH_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String USERNAME_ATTRIBUTE = "username";
    private static final String ROLE_ATTRIBUTE = "role";

    private final TokenVerificationClient tokenVerificationClient;

    protected AbstractAuthInterceptor(TokenVerificationClient tokenVerificationClient) {
        this.tokenVerificationClient = tokenVerificationClient;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws IOException {
        String authHeader = request.getHeader(AUTH_HEADER);
        if (authHeader == null || authHeader.isEmpty()) {
            sendJsonError(response, HttpServletResponse.SC_UNAUTHORIZED, "Token manquant");
            return false;
        }

        String token = authHeader.startsWith(BEARER_PREFIX) ? authHeader.substring(BEARER_PREFIX.length()) : authHeader;

        TokenVerificationResult result = tokenVerificationClient.verify(token);

        if (result instanceof TokenVerificationResult.Rejected rejected) {
            sendJsonError(response, HttpServletResponse.SC_UNAUTHORIZED, rejected.message());
            return false;
        }
        if (result instanceof TokenVerificationResult.Unreachable unreachable) {
            sendJsonError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, unreachable.message());
            return false;
        }

        TokenVerificationResult.Valid valid = (TokenVerificationResult.Valid) result;
        request.setAttribute(USERNAME_ATTRIBUTE, valid.user());
        request.setAttribute(ROLE_ATTRIBUTE, valid.role());

        if (!postAuthorize(request, response, valid)) {
            if (!response.isCommitted()) {
                sendJsonError(response, HttpServletResponse.SC_FORBIDDEN, "Accès refusé");
            }
            return false;
        }

        return true;
    }

    /**
     * Point d'extension pour la politique d'autorisation propre à chaque service, appelé une fois
     * le token authentifié comme valide. Par défaut, autorise toute requête authentifiée.
     * Une implémentation qui refuse l'accès peut écrire elle-même une réponse personnalisée dans
     * {@code response} avant de retourner {@code false} ; sinon un 403 générique est renvoyé.
     */
    protected boolean postAuthorize(HttpServletRequest request, HttpServletResponse response,
            TokenVerificationResult.Valid authenticatedUser) {
        return true;
    }

    private void sendJsonError(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"error\": \"" + message + "\"}");
        response.getWriter().flush();
    }
}
