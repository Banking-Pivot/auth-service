package com.banking.authservice.infrastructure.adapter.out.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ConfiguredServiceClientsTest {

  private final ConfiguredServiceClients clients =
      new ConfiguredServiceClients(
          Map.of("account-service", "account-secret", "credit-service", "credit-secret"));

  @Test
  void aRegisteredClientAuthenticatesOnlyWithItsOwnSecret() {
    assertThat(clients.authenticates("account-service", "account-secret")).isTrue();
    assertThat(clients.authenticates("account-service", "credit-secret")).isFalse();
    assertThat(clients.authenticates("account-service", "Account-Secret")).isFalse();
    assertThat(clients.authenticates("account-service", "")).isFalse();
    assertThat(clients.authenticates("account-service", null)).isFalse();
  }

  @Test
  void anUnknownClientNeverAuthenticates() {
    assertThat(clients.authenticates("card-service", "account-secret")).isFalse();
    assertThat(clients.authenticates(null, "account-secret")).isFalse();
    // Not even with the text an unknown client is compared against.
    assertThat(clients.authenticates("card-service", "no client is registered under this name"))
        .isFalse();
  }

  @Test
  void aClientWithoutSecretCannotAuthenticate() {
    Map<String, String> secrets = new HashMap<>();
    secrets.put("account-service", " ");
    secrets.put("credit-service", null);
    ConfiguredServiceClients withoutSecrets = new ConfiguredServiceClients(secrets);

    assertThat(withoutSecrets.authenticates("account-service", " ")).isFalse();
    assertThat(withoutSecrets.authenticates("credit-service", "")).isFalse();
    assertThat(withoutSecrets.authenticates("credit-service", null)).isFalse();
  }
}
