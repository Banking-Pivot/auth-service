package com.banking.authservice.support;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;

/** Reads and verifies access tokens the way a resource server does. */
public final class Tokens {

  private Tokens() {}

  public static SignedJWT parse(String token) {
    try {
      return SignedJWT.parse(token);
    } catch (ParseException e) {
      throw new AssertionError("Not a signed JWT", e);
    }
  }

  public static JWTClaimsSet claims(String token) {
    try {
      return parse(token).getJWTClaimsSet();
    } catch (ParseException e) {
      throw new AssertionError("The claims cannot be read", e);
    }
  }

  /** Whether the public key of the modulus and exponent verifies the signature of the token. */
  public static boolean verifies(String token, String modulus, String exponent) {
    try {
      RSAKey key = new RSAKey.Builder(new Base64URL(modulus), new Base64URL(exponent)).build();
      return parse(token).verify(new RSASSAVerifier(key.toRSAPublicKey()));
    } catch (JOSEException e) {
      throw new AssertionError("The signature cannot be checked", e);
    }
  }

  /** Whether the key of the JWK Set named by the {@code kid} of the token verifies it. */
  public static boolean verifiesWithJwkSet(String token, String jwkSetJson) {
    try {
      SignedJWT signed = parse(token);
      JWK key = JWKSet.parse(jwkSetJson).getKeyByKeyId(signed.getHeader().getKeyID());
      return key != null && signed.verify(new RSASSAVerifier(key.toRSAKey().toRSAPublicKey()));
    } catch (ParseException | JOSEException e) {
      throw new AssertionError("The signature cannot be checked", e);
    }
  }
}
