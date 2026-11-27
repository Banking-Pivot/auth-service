package com.banking.authservice.infrastructure.adapter.out.postgres;

import static org.assertj.core.api.Assertions.assertThat;

import com.banking.authservice.domain.model.enums.Role;
import com.banking.authservice.domain.model.vo.AccessToken;
import com.banking.authservice.domain.model.vo.VerificationKey;
import com.banking.authservice.infrastructure.adapter.out.security.PrivateKeyCipher;
import com.banking.authservice.infrastructure.adapter.out.security.RsaTokenSigner;
import com.banking.authservice.infrastructure.adapter.out.security.SigningKeyStore;
import com.banking.authservice.infrastructure.adapter.out.security.StoredSigningKey;
import com.banking.authservice.support.IntegrationTest;
import com.banking.authservice.support.Tokens;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The signing key in the database: one row, the private key encrypted, the same after a restart.
 */
class SigningKeyPersistenceTest extends IntegrationTest {

  @Autowired private SigningKeyStore store;

  @Test
  void theKeyCreatedAtStartupIsStoredOnceWithThePrivateKeyEncrypted() throws Exception {
    StoredSigningKey stored = store.find().block();

    assertThat(keyCount()).isEqualTo(1);
    assertThat(jwkSet()).contains("\"kid\":\"" + stored.keyId() + "\"");
    // What the secret kept in Vault opens is a PKCS#8 private key; what is stored is not one.
    byte[] privateKey =
        new PrivateKeyCipher(KEY_ENCRYPTION_SECRET)
            .decrypt(stored.encryptedPrivateKey(), stored.keyId());
    assertThat(privateKey).hasSizeGreaterThan(1000);
    assertThat(
            new String(
                Base64.getDecoder().decode(stored.encryptedPrivateKey()),
                StandardCharsets.ISO_8859_1))
        .doesNotContain(
            new String(Arrays.copyOfRange(privateKey, 0, 16), StandardCharsets.ISO_8859_1));
  }

  @Test
  void aServiceThatRestartsSignsWithTheStoredKey() {
    String published = jwkSet();
    RsaTokenSigner restarted =
        new RsaTokenSigner(
            store,
            new PrivateKeyCipher(KEY_ENCRYPTION_SECRET),
            "banking-auth",
            Duration.ofMinutes(15),
            Clock.systemUTC(),
            UUID::randomUUID);

    AccessToken token = restarted.sign("ana", Set.of(Role.USER)).block();
    VerificationKey key = restarted.verificationKeys().block().get(0);

    assertThat(Tokens.verifiesWithJwkSet(token.value(), published)).isTrue();
    assertThat(published).contains("\"n\":\"" + key.modulus() + "\"");
    assertThat(keyCount()).isEqualTo(1);
  }

  @Test
  void aSecondKeyIsNotStoredAndDeletingAnUnknownOneChangesNothing() {
    StoredSigningKey stored = store.find().block();
    StoredSigningKey other =
        new StoredSigningKey("another-key", stored.publicKey(), "ZW5jcnlwdGVk", Instant.now());

    assertThat(store.insert(other).block()).isFalse();
    store.delete("another-key").block();

    assertThat(store.find().block().keyId()).isEqualTo(stored.keyId());
    assertThat(keyCount()).isEqualTo(1);
  }

  private long keyCount() {
    return databaseClient
        .sql("SELECT count(*) FROM signing_keys")
        .map(row -> row.get(0, Long.class))
        .one()
        .block();
  }
}
