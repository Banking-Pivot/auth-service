package com.banking.authservice.infrastructure.adapter.out.security;

import java.time.Instant;

/**
 * The signing key as it is stored.
 *
 * @param keyId identifier of the key
 * @param publicKey public key, X.509 encoded, in base64
 * @param encryptedPrivateKey private key, as {@link PrivateKeyCipher} encrypted it
 * @param createdAt when the key was created
 */
public record StoredSigningKey(
    String keyId, String publicKey, String encryptedPrivateKey, Instant createdAt) {

  /** Leaves the key material out. */
  @Override
  public String toString() {
    return "StoredSigningKey[keyId=" + keyId + ", createdAt=" + createdAt + "]";
  }
}
