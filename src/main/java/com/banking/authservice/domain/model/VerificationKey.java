package com.banking.authservice.domain.model;

/**
 * The public half of the RSA key that signs the access tokens, as a JWK publishes it.
 *
 * @param keyId identifier of the key; the tokens it signed carry it as {@code kid}
 * @param modulus modulus of the key, base64url
 * @param exponent public exponent of the key, base64url
 */
public record VerificationKey(String keyId, String modulus, String exponent) {

  public static final String KEY_TYPE = "RSA";
  public static final String USE = "sig";
  public static final String ALGORITHM = "RS256";
}
