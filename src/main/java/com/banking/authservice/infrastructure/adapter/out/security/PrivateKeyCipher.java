package com.banking.authservice.infrastructure.adapter.out.security;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypts the private signing key before it is stored, so a copy of the database alone cannot sign
 * tokens: the secret that opens it only lives in Vault.
 *
 * <p>AES-256 in GCM mode. The AES key is derived from the secret with PBKDF2 and a random salt; the
 * identifier of the signing key is authenticated with the ciphertext, so an encrypted key cannot be
 * moved under another identifier. What is stored is base64 of salt, nonce and ciphertext, in that
 * order.
 */
public final class PrivateKeyCipher {

  private static final String TRANSFORMATION = "AES/GCM/NoPadding";
  private static final String DERIVATION = "PBKDF2WithHmacSHA256";
  private static final int DERIVATION_ITERATIONS = 100_000;
  private static final int KEY_BITS = 256;
  private static final int SALT_BYTES = 16;
  private static final int NONCE_BYTES = 12;
  private static final int TAG_BITS = 128;

  private final char[] secret;
  private final SecureRandom random = new SecureRandom();

  public PrivateKeyCipher(String secret) {
    this.secret = secret.toCharArray();
  }

  /**
   * Encrypts a private key.
   *
   * @param privateKey the key, encoded
   * @param keyId identifier of the signing key it belongs to
   * @return what to store
   */
  public String encrypt(byte[] privateKey, String keyId) {
    byte[] salt = randomBytes(SALT_BYTES);
    byte[] nonce = randomBytes(NONCE_BYTES);
    try {
      byte[] encrypted = cipher(Cipher.ENCRYPT_MODE, salt, nonce, keyId).doFinal(privateKey);
      ByteBuffer stored = ByteBuffer.allocate(salt.length + nonce.length + encrypted.length);
      stored.put(salt).put(nonce).put(encrypted);
      return Base64.getEncoder().encodeToString(stored.array());
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("The signing key could not be encrypted", e);
    }
  }

  /**
   * Decrypts what {@link #encrypt(byte[], String)} wrote.
   *
   * @param stored the stored value
   * @param keyId identifier of the signing key it belongs to
   * @return the private key, encoded
   * @throws GeneralSecurityException when the value was written with another secret, belongs to
   *     another key or was altered
   */
  public byte[] decrypt(String stored, String keyId) throws GeneralSecurityException {
    byte[] bytes;
    try {
      bytes = Base64.getDecoder().decode(stored);
    } catch (IllegalArgumentException e) {
      throw new GeneralSecurityException("The stored key is not base64", e);
    }
    if (bytes.length <= SALT_BYTES + NONCE_BYTES) {
      throw new GeneralSecurityException("The stored key is too short");
    }
    byte[] salt = Arrays.copyOfRange(bytes, 0, SALT_BYTES);
    byte[] nonce = Arrays.copyOfRange(bytes, SALT_BYTES, SALT_BYTES + NONCE_BYTES);
    byte[] encrypted = Arrays.copyOfRange(bytes, SALT_BYTES + NONCE_BYTES, bytes.length);
    return cipher(Cipher.DECRYPT_MODE, salt, nonce, keyId).doFinal(encrypted);
  }

  private Cipher cipher(int mode, byte[] salt, byte[] nonce, String keyId)
      throws GeneralSecurityException {
    PBEKeySpec specification = new PBEKeySpec(secret, salt, DERIVATION_ITERATIONS, KEY_BITS);
    byte[] derived =
        SecretKeyFactory.getInstance(DERIVATION).generateSecret(specification).getEncoded();
    SecretKey key = new SecretKeySpec(derived, "AES");
    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    cipher.init(mode, key, new GCMParameterSpec(TAG_BITS, nonce));
    cipher.updateAAD(keyId.getBytes(StandardCharsets.UTF_8));
    return cipher;
  }

  private byte[] randomBytes(int length) {
    byte[] bytes = new byte[length];
    random.nextBytes(bytes);
    return bytes;
  }
}
