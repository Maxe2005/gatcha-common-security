package com.imt.commonsecurity.auth;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record AuthTokenResponse(String user, String role) {
}
