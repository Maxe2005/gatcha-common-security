package com.imt.commonsecurity.devauth;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Réponse de {@code GET /token} exposée par le sidecar {@code dev-token-provider} (Story 1.1). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record DevTokenResponse(String token) {
}
