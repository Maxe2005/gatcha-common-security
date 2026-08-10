package com.imt.commonsecurity.devauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

@ExtendWith(MockitoExtension.class)
class DevTokenClientTest {

    @Mock
    private RestTemplate restTemplate;

    private DevTokenClient client;

    private void init() {
        client = new DevTokenClient(restTemplate, "http://dev-token-provider", "9876");
    }

    @Test
    void fetchToken_returnsToken_whenSidecarRespondsOk() {
        init();
        when(restTemplate.getForEntity(eq("http://dev-token-provider:9876/token"), eq(DevTokenResponse.class)))
                .thenReturn(new ResponseEntity<>(new DevTokenResponse("dev-token-1"), HttpStatus.OK));

        Optional<String> token = client.fetchToken();

        assertThat(token).contains("dev-token-1");
    }

    @Test
    void fetchToken_returnsEmpty_whenSidecarHasNoTokenYet() {
        init();
        when(restTemplate.getForEntity(any(String.class), eq(DevTokenResponse.class)))
                .thenReturn(new ResponseEntity<>(HttpStatus.SERVICE_UNAVAILABLE));

        assertThat(client.fetchToken()).isEmpty();
    }

    @Test
    void fetchToken_returnsEmpty_neverThrows_whenSidecarUnreachable() {
        init();
        when(restTemplate.getForEntity(any(String.class), eq(DevTokenResponse.class)))
                .thenThrow(new ResourceAccessException("connection refused"));

        assertThat(client.fetchToken()).isEmpty();
    }
}
