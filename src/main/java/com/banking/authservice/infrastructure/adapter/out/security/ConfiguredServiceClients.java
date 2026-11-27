package com.banking.authservice.infrastructure.adapter.out.security;

import com.banking.authservice.application.port.out.ServiceClientsPort;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * The service clients of the settings: client ID to secret, the secrets read from Vault.
 *
 * <p>Secrets are compared through their SHA-256 digests with a comparison that takes the same time
 * whether they differ in the first byte or in the last, and an unknown client is compared too, so
 * the time of the answer tells nothing about the secret or about which clients exist.
 */
public class ConfiguredServiceClients implements ServiceClientsPort {

  private static final byte[] NO_CLIENT = digest("no client is registered under this name");

  private final Map<String, byte[]> secretDigests;

  /**
   * Keeps the digest of every secret. A client without a secret is left out: it can never
   * authenticate.
   *
   * @param secrets client ID to secret
   */
  public ConfiguredServiceClients(Map<String, String> secrets) {
    this.secretDigests =
        secrets.entrySet().stream()
            .filter(client -> client.getValue() != null && !client.getValue().isBlank())
            .collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, c -> digest(c.getValue())));
  }

  @Override
  public boolean authenticates(String clientId, String clientSecret) {
    byte[] expected = clientId == null ? null : secretDigests.get(clientId);
    byte[] presented = digest(clientSecret == null ? "" : clientSecret);
    boolean same = MessageDigest.isEqual(presented, expected == null ? NO_CLIENT : expected);
    return same && expected != null;
  }

  private static byte[] digest(String secret) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(secret.getBytes(StandardCharsets.UTF_8));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is not available", e);
    }
  }
}
