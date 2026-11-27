package com.banking.authservice.infrastructure.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

class AuthPropertiesTest {

  @Test
  void theTextOfTheSettingsNeverShowsASecret() {
    AuthProperties properties =
        new AuthProperties(
            new AuthProperties.Jwt("banking-auth", Duration.ofHours(1), "the-key-secret-12345"),
            new AuthProperties.Bootstrap("admin", "the-admin-password"),
            new AuthProperties.Passwords(10),
            new AuthProperties.Login(5, Duration.ofMinutes(15)),
            Map.of("account-service", "the-client-secret"));

    assertThat(properties.toString())
        .contains("banking-auth", "admin", "account-service", "PT1H", "PT15M")
        .doesNotContain("the-key-secret-12345", "the-admin-password", "the-client-secret");
  }

  @Test
  void aUserIsLockedAfterFiveWrongPasswordsForFifteenMinutesUnlessTheSettingsSayOtherwise() {
    AuthProperties.Login byDefault = bound(Map.of()).login();
    AuthProperties.Login configured =
        bound(Map.of("auth.login.max-failed-attempts", "3", "auth.login.lock-duration", "10m"))
            .login();

    assertThat(byDefault.maxFailedAttempts()).isEqualTo(5);
    assertThat(byDefault.lockDuration()).isEqualTo(Duration.ofMinutes(15));
    assertThat(configured.maxFailedAttempts()).isEqualTo(3);
    assertThat(configured.lockDuration()).isEqualTo(Duration.ofMinutes(10));
  }

  private static AuthProperties bound(Map<String, String> settings) {
    return new Binder(new MapConfigurationPropertySource(settings))
        .bindOrCreate("auth", AuthProperties.class);
  }

  @Test
  void noServiceClientsConfiguredMeansNone() {
    AuthProperties properties =
        new AuthProperties(
            new AuthProperties.Jwt("banking-auth", Duration.ofHours(1), "the-key-secret-12345"),
            new AuthProperties.Bootstrap("admin", "the-admin-password"),
            new AuthProperties.Passwords(10),
            new AuthProperties.Login(5, Duration.ofMinutes(15)),
            null);

    assertThat(properties.serviceClients()).isEmpty();
  }
}
