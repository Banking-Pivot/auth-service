package com.banking.authservice.infrastructure.adapter.out.security;

import com.banking.authservice.application.port.out.TokenSignerPort;
import com.banking.authservice.domain.model.enums.Role;
import com.banking.authservice.domain.model.vo.AccessToken;
import com.banking.authservice.domain.model.vo.VerificationKey;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Signs the access tokens with RS256 and publishes the public key that verifies them.
 *
 * <p>The RSA key pair is created the first time it is needed and stored with the private key
 * encrypted, so every later start, and every other instance, signs with the same key and the tokens
 * in use stay valid. Once read, the key is kept in memory. A stored key that cannot be opened with
 * the configured secret (the secret was changed) is replaced by a new one.
 *
 * <p>Token: header {@code alg}, {@code kid}, {@code typ}; claims {@code iss}, {@code sub}, {@code
 * roles}, {@code iat}, {@code exp} and {@code jti}.
 */
@Slf4j
public class RsaTokenSigner implements TokenSignerPort {

  /** Name of the claim with the roles, an array of strings. */
  public static final String ROLES_CLAIM = "roles";

  private static final String RSA = "RSA";
  private static final int KEY_BITS = 2048;
  private static final Duration FOREVER = Duration.ofMillis(Long.MAX_VALUE);

  private final SigningKeyStore store;
  private final PrivateKeyCipher cipher;
  private final String issuer;
  private final Duration lifetime;
  private final Clock clock;
  private final Supplier<UUID> identifiers;
  private final Mono<RSAKey> signingKey;

  /**
   * Creates the signer. The key is read or created on first use, not here.
   *
   * @param store where the key is kept
   * @param cipher what encrypts the private key for the store
   * @param issuer value of the {@code iss} claim
   * @param lifetime how long a token is valid
   * @param clock source of the issue instant
   * @param identifiers source of token identifiers and of the identifier of a new key
   */
  public RsaTokenSigner(
      SigningKeyStore store,
      PrivateKeyCipher cipher,
      String issuer,
      Duration lifetime,
      Clock clock,
      Supplier<UUID> identifiers) {
    this.store = store;
    this.cipher = cipher;
    this.issuer = issuer;
    this.lifetime = lifetime;
    this.clock = clock;
    this.identifiers = identifiers;
    // A failure is not remembered: the next token tries the database again.
    this.signingKey =
        Mono.defer(this::loadOrCreate)
            .cache(key -> FOREVER, error -> Duration.ZERO, () -> Duration.ZERO);
  }

  @Override
  public Mono<AccessToken> sign(String subject, Set<Role> roles) {
    return signingKey.map(key -> signed(key, subject, roles));
  }

  @Override
  public Mono<List<VerificationKey>> verificationKeys() {
    return signingKey.map(
        key ->
            List.of(
                new VerificationKey(
                    key.getKeyID(),
                    key.getModulus().toString(),
                    key.getPublicExponent().toString())));
  }

  private AccessToken signed(RSAKey key, String subject, Set<Role> roles) {
    Instant now = clock.instant();
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject(subject)
            .claim(ROLES_CLAIM, roles.stream().map(Enum::name).sorted().toList())
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plus(lifetime)))
            .jwtID(identifiers.get().toString())
            .build();
    JWSHeader header =
        new JWSHeader.Builder(JWSAlgorithm.RS256)
            .keyID(key.getKeyID())
            .type(JOSEObjectType.JWT)
            .build();
    SignedJWT token = new SignedJWT(header, claims);
    try {
      token.sign(new RSASSASigner(key));
    } catch (JOSEException e) {
      throw new IllegalStateException("The access token could not be signed", e);
    }
    return new AccessToken(token.serialize(), lifetime.toSeconds(), roles);
  }

  private Mono<RSAKey> loadOrCreate() {
    return store
        .find()
        .flatMap(stored -> restore(stored).map(Mono::just).orElseGet(() -> replace(stored)))
        .switchIfEmpty(Mono.defer(this::create));
  }

  private Optional<RSAKey> restore(StoredSigningKey stored) {
    try {
      KeyFactory factory = KeyFactory.getInstance(RSA);
      byte[] publicKey = Base64.getDecoder().decode(stored.publicKey());
      byte[] privateKey = cipher.decrypt(stored.encryptedPrivateKey(), stored.keyId());
      return Optional.of(
          jwk(
              stored.keyId(),
              (RSAPublicKey) factory.generatePublic(new X509EncodedKeySpec(publicKey)),
              (RSAPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey))));
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      // Neither the secret nor the key material goes to the log.
      log.warn(
          "Signing key {} cannot be opened with the configured encryption secret ({}). A new key"
              + " replaces it and the tokens signed with the old one stop being valid.",
          stored.keyId(),
          e.getClass().getSimpleName());
      return Optional.empty();
    }
  }

  private Mono<RSAKey> replace(StoredSigningKey unreadable) {
    return store.delete(unreadable.keyId()).then(Mono.defer(this::create));
  }

  // Generating an RSA key takes a noticeable fraction of a second: off the request threads.
  private Mono<RSAKey> create() {
    return Mono.fromCallable(this::generate)
        .subscribeOn(Schedulers.boundedElastic())
        .flatMap(
            generated ->
                store
                    .insert(generated.stored())
                    .flatMap(
                        inserted ->
                            Boolean.TRUE.equals(inserted)
                                ? Mono.just(generated.key())
                                // Another instance stored its key first: use that one.
                                : Mono.defer(this::loadOrCreate)));
  }

  private Generated generate() {
    KeyPair pair;
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA);
      generator.initialize(KEY_BITS);
      pair = generator.generateKeyPair();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("The signing key could not be generated", e);
    }
    String keyId = identifiers.get().toString();
    StoredSigningKey stored =
        new StoredSigningKey(
            keyId,
            Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()),
            cipher.encrypt(pair.getPrivate().getEncoded(), keyId),
            clock.instant());
    log.info("Signing key {} created.", keyId);
    return new Generated(
        jwk(keyId, (RSAPublicKey) pair.getPublic(), (RSAPrivateKey) pair.getPrivate()), stored);
  }

  private static RSAKey jwk(String keyId, RSAPublicKey publicKey, RSAPrivateKey privateKey) {
    return new RSAKey.Builder(publicKey)
        .privateKey(privateKey)
        .keyID(keyId)
        .keyUse(KeyUse.SIGNATURE)
        .algorithm(JWSAlgorithm.RS256)
        .build();
  }

  private record Generated(RSAKey key, StoredSigningKey stored) {}
}
