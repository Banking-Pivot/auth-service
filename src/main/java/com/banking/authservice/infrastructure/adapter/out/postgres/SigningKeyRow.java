package com.banking.authservice.infrastructure.adapter.out.postgres;

import com.banking.authservice.infrastructure.adapter.out.security.StoredSigningKey;
import java.time.Instant;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

/** Row of {@code signing_keys}. The unique {@code purpose} keeps the table at one row. */
@Table("signing_keys")
public record SigningKeyRow(
    @Id String keyId,
    String purpose,
    String publicKey,
    String encryptedPrivateKey,
    Instant createdAt) {

  static final String ACCESS_TOKEN = "ACCESS_TOKEN";

  static SigningKeyRow of(StoredSigningKey key) {
    return new SigningKeyRow(
        key.keyId(), ACCESS_TOKEN, key.publicKey(), key.encryptedPrivateKey(), key.createdAt());
  }

  StoredSigningKey toStoredKey() {
    return new StoredSigningKey(keyId, publicKey, encryptedPrivateKey, createdAt);
  }

  /** Leaves the key material out. */
  @Override
  public String toString() {
    return "SigningKeyRow[keyId=" + keyId + ", createdAt=" + createdAt + "]";
  }
}
