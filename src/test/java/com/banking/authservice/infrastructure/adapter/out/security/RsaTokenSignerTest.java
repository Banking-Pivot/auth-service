package com.banking.authservice.infrastructure.adapter.out.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.banking.authservice.domain.model.AccessToken;
import com.banking.authservice.domain.model.Role;
import com.banking.authservice.domain.model.VerificationKey;
import com.banking.authservice.support.InMemorySigningKeyStore;
import com.banking.authservice.support.Tokens;
import com.banking.authservice.support.Users;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import java.text.ParseException;
import java.time.Duration;
import java.util.Date;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class RsaTokenSignerTest {

  private static final String SECRET = "the-secret-kept-in-vault";

  private final InMemorySigningKeyStore store = new InMemorySigningKeyStore();
  private final RsaTokenSigner signer = signer(store, SECRET);

  @Test
  void aTokenCarriesItsClaimsAndThePublishedKeyVerifiesIt() throws ParseException {
    AccessToken token = signer.sign("ana", Set.of(Role.USER, Role.ADMIN)).block();
    VerificationKey key = signer.verificationKeys().block().get(0);

    assertThat(token.expiresInSeconds()).isEqualTo(900);
    assertThat(token.roles()).containsExactlyInAnyOrder(Role.ADMIN, Role.USER);
    assertThat(Tokens.verifies(token.value(), key.modulus(), key.exponent())).isTrue();

    JWSHeader header = Tokens.parse(token.value()).getHeader();
    assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
    assertThat(header.getType()).isEqualTo(JOSEObjectType.JWT);
    assertThat(header.getKeyID()).isEqualTo(key.keyId());

    JWTClaimsSet claims = Tokens.claims(token.value());
    assertThat(claims.getIssuer()).isEqualTo("banking-auth");
    assertThat(claims.getSubject()).isEqualTo("ana");
    assertThat(claims.getStringListClaim(RsaTokenSigner.ROLES_CLAIM))
        .containsExactly("ADMIN", "USER");
    assertThat(claims.getIssueTime()).isEqualTo(Date.from(Users.NOW));
    assertThat(claims.getExpirationTime()).isEqualTo(Date.from(Users.NOW.plusSeconds(900)));
    assertThat(UUID.fromString(claims.getJWTID())).isNotNull();
  }

  @Test
  void everyTokenHasItsOwnIdentifier() {
    String first = signer.sign("ana", Set.of(Role.USER)).block().value();
    String second = signer.sign("ana", Set.of(Role.USER)).block().value();

    assertThat(Tokens.claims(first).getJWTID()).isNotEqualTo(Tokens.claims(second).getJWTID());
  }

  @Test
  void theKeyIsCreatedOnceStoredEncryptedAndKeptInMemory() {
    signer.sign("ana", Set.of(Role.USER)).block();
    signer.sign("admin", Set.of(Role.ADMIN)).block();
    signer.verificationKeys().block();

    assertThat(store.inserts()).isEqualTo(1);
    assertThat(store.finds()).isEqualTo(1);
    assertThat(store.current().keyId()).isEqualTo(signer.verificationKeys().block().get(0).keyId());
    assertThat(store.current().toString()).doesNotContain(store.current().publicKey());
  }

  @Test
  void anotherSignerWithTheSameSecretSignsWithTheStoredKey() {
    VerificationKey key = signer.verificationKeys().block().get(0);
    RsaTokenSigner restarted = signer(store, SECRET);

    AccessToken token = restarted.sign("ana", Set.of(Role.USER)).block();

    assertThat(restarted.verificationKeys().block()).containsExactly(key);
    assertThat(Tokens.verifies(token.value(), key.modulus(), key.exponent())).isTrue();
    assertThat(store.inserts()).isEqualTo(1);
  }

  @Test
  void aKeyStoredUnderAnotherSecretIsReplacedByANewOne() {
    VerificationKey old = signer.verificationKeys().block().get(0);
    RsaTokenSigner withAnotherSecret = signer(store, "another-secret-entirely");

    AccessToken token = withAnotherSecret.sign("ana", Set.of(Role.USER)).block();
    VerificationKey replacement = withAnotherSecret.verificationKeys().block().get(0);

    assertThat(replacement.keyId()).isNotEqualTo(old.keyId()).isEqualTo(store.current().keyId());
    assertThat(Tokens.verifies(token.value(), replacement.modulus(), replacement.exponent()))
        .isTrue();
    assertThat(Tokens.verifies(token.value(), old.modulus(), old.exponent())).isFalse();
    assertThat(store.inserts()).isEqualTo(2);
  }

  @Test
  void whenAnotherInstanceStoresItsKeyFirstThatKeyIsUsed() {
    InMemorySigningKeyStore shared = new InMemorySigningKeyStore();
    VerificationKey first = signer.verificationKeys().block().get(0);
    shared.loseTheRaceTo(store.current());

    RsaTokenSigner second = signer(shared, SECRET);

    assertThat(second.verificationKeys().block()).containsExactly(first);
    assertThat(shared.inserts()).isZero();
  }

  @Test
  void aFailureReadingTheKeyIsNotRemembered() {
    store.failNextFind();

    assertThatThrownBy(() -> signer.sign("ana", Set.of(Role.USER)).block())
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("database unreachable");
    assertThat(signer.sign("ana", Set.of(Role.USER)).block().value()).isNotBlank();
  }

  private static RsaTokenSigner signer(InMemorySigningKeyStore store, String secret) {
    return new RsaTokenSigner(
        store,
        new PrivateKeyCipher(secret),
        "banking-auth",
        Duration.ofMinutes(15),
        Users.CLOCK,
        UUID::randomUUID);
  }
}
