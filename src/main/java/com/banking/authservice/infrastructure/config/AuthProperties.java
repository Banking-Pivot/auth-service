package com.banking.authservice.infrastructure.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Duration;
import java.util.Map;
import org.hibernate.validator.constraints.time.DurationMin;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * Settings of Auth Service under {@code auth}. The issuer, the lifetime of the tokens, the cost of
 * the password hash and the lock after wrong passwords are served by the Config Server; every
 * secret comes from Vault.
 *
 * @param jwt how the access tokens are issued and signed
 * @param bootstrap the first administrator
 * @param passwords how passwords are hashed
 * @param login when wrong passwords lock a user
 * @param serviceClients services allowed to ask for a service token: client ID to secret
 */
@Validated
@ConfigurationProperties("auth")
public record AuthProperties(
    @NotNull @Valid @DefaultValue Jwt jwt,
    @NotNull @Valid @DefaultValue Bootstrap bootstrap,
    @NotNull @Valid @DefaultValue Passwords passwords,
    @NotNull @Valid @DefaultValue Login login,
    Map<String, String> serviceClients) {

  /** Copies the service clients; none configured means no service can get a token. */
  public AuthProperties {
    serviceClients = serviceClients == null ? Map.of() : Map.copyOf(serviceClients);
  }

  /** Leaves the secrets out. */
  @Override
  public String toString() {
    return "AuthProperties[jwt="
        + jwt
        + ", bootstrap="
        + bootstrap
        + ", passwords="
        + passwords
        + ", login="
        + login
        + ", serviceClients="
        + serviceClients.keySet()
        + "]";
  }

  /**
   * The access tokens.
   *
   * @param issuer value of the {@code iss} claim; the API Gateway only accepts this issuer
   * @param accessTokenTtl how long a token is valid
   * @param keyEncryptionSecret secret the private signing key is encrypted with before it is
   *     stored; from Vault
   */
  public record Jwt(
      @DefaultValue("banking-auth") @NotBlank String issuer,
      @DefaultValue("1h") @NotNull Duration accessTokenTtl,
      @NotBlank @Size(min = 16) String keyEncryptionSecret) {

    /** Leaves the secret out. */
    @Override
    public String toString() {
      return "Jwt[issuer=" + issuer + ", accessTokenTtl=" + accessTokenTtl + "]";
    }
  }

  /**
   * The administrator created at startup when no user has its name.
   *
   * @param adminUsername name of that user
   * @param adminPassword password it is created with; from Vault
   */
  public record Bootstrap(
      @DefaultValue("admin") @NotBlank @Pattern(regexp = "[a-z0-9][a-z0-9._-]{2,49}")
          String adminUsername,
      @NotBlank @Size(min = 8, max = 72) String adminPassword) {

    /** Leaves the password out. */
    @Override
    public String toString() {
      return "Bootstrap[adminUsername=" + adminUsername + "]";
    }
  }

  /**
   * Password hashing.
   *
   * @param bcryptStrength cost of BCrypt: each step up doubles the time a hash takes
   */
  public record Passwords(@DefaultValue("10") @Min(4) @Max(15) int bcryptStrength) {}

  /**
   * The lock of a user after wrong passwords.
   *
   * @param maxFailedAttempts wrong passwords in a row that lock the user
   * @param lockDuration how long a locked user is refused, also with the right password
   */
  public record Login(
      @DefaultValue("5") @Min(1) int maxFailedAttempts,
      @DefaultValue("15m") @NotNull @DurationMin(seconds = 1) Duration lockDuration) {}
}
