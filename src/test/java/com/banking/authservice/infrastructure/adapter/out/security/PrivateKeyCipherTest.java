package com.banking.authservice.infrastructure.adapter.out.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class PrivateKeyCipherTest {

  private static final byte[] KEY = "not really a private key".getBytes(StandardCharsets.UTF_8);

  private final PrivateKeyCipher cipher = new PrivateKeyCipher("the-secret-kept-in-vault");

  @Test
  void whatIsEncryptedComesBackWithTheSameSecretAndKeyId() throws GeneralSecurityException {
    String stored = cipher.encrypt(KEY, "key-1");

    assertThat(cipher.decrypt(stored, "key-1")).isEqualTo(KEY);
    assertThat(new PrivateKeyCipher("the-secret-kept-in-vault").decrypt(stored, "key-1"))
        .isEqualTo(KEY);
  }

  @Test
  void theStoredValueDoesNotContainTheKeyAndIsDifferentEveryTime() {
    String first = cipher.encrypt(KEY, "key-1");
    String second = cipher.encrypt(KEY, "key-1");

    assertThat(first).isNotEqualTo(second);
    assertThat(new String(Base64.getDecoder().decode(first), StandardCharsets.ISO_8859_1))
        .doesNotContain("not really a private key");
  }

  @Test
  void anotherSecretCannotOpenIt() {
    String stored = cipher.encrypt(KEY, "key-1");

    assertThatThrownBy(() -> new PrivateKeyCipher("another-secret-12345").decrypt(stored, "key-1"))
        .isInstanceOf(GeneralSecurityException.class);
  }

  @Test
  void itCannotBeMovedUnderAnotherKeyId() {
    String stored = cipher.encrypt(KEY, "key-1");

    assertThatThrownBy(() -> cipher.decrypt(stored, "key-2"))
        .isInstanceOf(GeneralSecurityException.class);
  }

  @Test
  void anAlteredOrUnreadableValueIsRejected() {
    byte[] altered = Base64.getDecoder().decode(cipher.encrypt(KEY, "key-1"));
    altered[altered.length - 1] ^= 1;

    assertThatThrownBy(() -> cipher.decrypt(Base64.getEncoder().encodeToString(altered), "key-1"))
        .isInstanceOf(GeneralSecurityException.class);
    assertThatThrownBy(() -> cipher.decrypt("not base64 !!", "key-1"))
        .isInstanceOf(GeneralSecurityException.class)
        .hasMessageContaining("base64");
    assertThatThrownBy(() -> cipher.decrypt("c2hvcnQ=", "key-1"))
        .isInstanceOf(GeneralSecurityException.class)
        .hasMessageContaining("too short");
  }
}
