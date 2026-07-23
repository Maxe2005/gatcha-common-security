package com.imt.commonsecurity.auth;

/**
 * Résultat de la vérification d'un token auprès d'API_authentification.
 */
public sealed interface TokenVerificationResult {

    record Valid(String user, String role) implements TokenVerificationResult {
    }

    /** Token rejeté (4xx d'API_authentification, ou 5xx traité en fail-safe comme invalide) — doit se traduire en 401. */
    record Rejected(String message) implements TokenVerificationResult {
    }

    /** API_authentification est injoignable (pas de réponse HTTP du tout) — doit se traduire en 500. */
    record Unreachable(String message) implements TokenVerificationResult {
    }
}
