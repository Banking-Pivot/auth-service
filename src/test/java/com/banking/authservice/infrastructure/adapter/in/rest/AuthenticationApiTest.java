package com.banking.authservice.infrastructure.adapter.in.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.Role;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.TokenResponse;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.UserResponse;
import com.banking.authservice.support.IntegrationTest;
import com.banking.authservice.support.Tokens;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

/** Login, service tokens and the JWK Set, end to end against a real database and a real Vault. */
class AuthenticationApiTest extends IntegrationTest {

  @Test
  void theFirstAdministratorLogsInAndTheTokenIsNotToBeStored() {
    login(ADMIN, ADMIN_PASSWORD)
        .expectStatus()
        .isOk()
        .expectHeader()
        .valueEquals(HttpHeaders.CACHE_CONTROL, "no-store")
        .expectBody()
        .jsonPath("$.accessToken")
        .isNotEmpty()
        .jsonPath("$.tokenType")
        .isEqualTo("Bearer")
        .jsonPath("$.expiresIn")
        .isEqualTo(900)
        .jsonPath("$.roles.length()")
        .isEqualTo(1)
        .jsonPath("$.roles[0]")
        .isEqualTo("ADMIN")
        .jsonPath("$.length()")
        .isEqualTo(4);
  }

  @Test
  void theTokenIsSignedWithThePublishedKeyAndCarriesTheClaimsOfTheContract() throws ParseException {
    created("ana.perez", "USER", "ADMIN");

    TokenResponse response = loggedIn("Ana.Perez", PASSWORD);
    String token = response.getAccessToken();

    assertThat(response.getRoles()).containsExactly(Role.ADMIN, Role.USER);
    assertThat(Tokens.verifiesWithJwkSet(token, jwkSet())).isTrue();

    JWSHeader header = Tokens.parse(token).getHeader();
    assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
    assertThat(header.getType()).isEqualTo(JOSEObjectType.JWT);
    assertThat(header.getKeyID()).isNotBlank();

    JWTClaimsSet claims = Tokens.claims(token);
    assertThat(claims.getIssuer()).isEqualTo("banking-auth");
    assertThat(claims.getSubject()).isEqualTo("ana.perez");
    assertThat(claims.getStringListClaim("roles")).containsExactly("ADMIN", "USER");
    assertThat(claims.getIssueTime().toInstant())
        .isCloseTo(Instant.now(), within(1, ChronoUnit.MINUTES));
    assertThat(
            ChronoUnit.SECONDS.between(
                claims.getIssueTime().toInstant(), claims.getExpirationTime().toInstant()))
        .isEqualTo(response.getExpiresIn())
        .isEqualTo(900);
    assertThat(UUID.fromString(claims.getJWTID())).isNotNull();
    assertThat(claims.getClaims()).containsOnlyKeys("iss", "sub", "roles", "iat", "exp", "jti");
  }

  @Test
  void theJwkSetPublishesOnlyThePublicPartOfTheKey() {
    webTestClient
        .get()
        .uri("/api/v1/auth/jwks")
        .exchange()
        .expectStatus()
        .isOk()
        .expectHeader()
        .contentTypeCompatibleWith(MediaType.APPLICATION_JSON)
        .expectBody()
        .jsonPath("$.keys.length()")
        .isEqualTo(1)
        .jsonPath("$.keys[0].kty")
        .isEqualTo("RSA")
        .jsonPath("$.keys[0].use")
        .isEqualTo("sig")
        .jsonPath("$.keys[0].alg")
        .isEqualTo("RS256")
        .jsonPath("$.keys[0].kid")
        .isNotEmpty()
        .jsonPath("$.keys[0].n")
        .isNotEmpty()
        .jsonPath("$.keys[0].e")
        .isEqualTo("AQAB")
        // Nothing of the private key: d, p, q, dp, dq, qi.
        .jsonPath("$.keys[0].length()")
        .isEqualTo(6);
  }

  @Test
  void aWrongPasswordAndAnUnknownUserGetTheSameAnswer() {
    expectError(login(ADMIN, "not-the-password"), 401, "INVALID_CREDENTIALS")
        .jsonPath("$.message")
        .isEqualTo("The username or the password is not correct.")
        .jsonPath("$.path")
        .isEqualTo("/api/v1/auth/login");
    expectError(login("nobody", ADMIN_PASSWORD), 401, "INVALID_CREDENTIALS")
        .jsonPath("$.message")
        .isEqualTo("The username or the password is not correct.");
  }

  @Test
  void aDisabledUserCannotLogInUntilItIsEnabledAgain() {
    UserResponse ana = created("ana", "USER");
    loggedIn("ana", PASSWORD);

    userAction(ana.getId(), "disable").expectStatus().isOk();
    expectError(login("ana", PASSWORD), 401, "INVALID_CREDENTIALS")
        .jsonPath("$.message")
        .isEqualTo("The username or the password is not correct.");

    userAction(ana.getId(), "enable").expectStatus().isOk();
    assertThat(loggedIn("ana", PASSWORD).getRoles()).containsExactly(Role.USER);
  }

  @Test
  void aRegisteredServiceGetsATokenWithTheRoleService() throws ParseException {
    TokenResponse response =
        serviceToken("account-service", ACCOUNT_SERVICE_SECRET)
            .expectStatus()
            .isOk()
            .expectHeader()
            .valueEquals(HttpHeaders.CACHE_CONTROL, "no-store")
            .expectBody(TokenResponse.class)
            .returnResult()
            .getResponseBody();

    assertThat(response.getTokenType()).isEqualTo(TokenResponse.TokenTypeEnum.BEARER);
    assertThat(response.getRoles()).containsExactly(Role.SERVICE);
    assertThat(response.getExpiresIn()).isEqualTo(900);
    assertThat(Tokens.verifiesWithJwkSet(response.getAccessToken(), jwkSet())).isTrue();
    JWTClaimsSet claims = Tokens.claims(response.getAccessToken());
    assertThat(claims.getSubject()).isEqualTo("account-service");
    assertThat(claims.getStringListClaim("roles")).containsExactly("SERVICE");
    assertThat(claims.getIssuer()).isEqualTo("banking-auth");

    serviceToken("credit-service", CREDIT_SERVICE_SECRET).expectStatus().isOk();
  }

  @Test
  void aWrongSecretAndAnUnknownClientGetTheSameAnswer() {
    expectError(serviceToken("account-service", CREDIT_SERVICE_SECRET), 401, "INVALID_CLIENT")
        .jsonPath("$.message")
        .isEqualTo("The client ID or the client secret is not correct.")
        .jsonPath("$.path")
        .isEqualTo("/api/v1/auth/service-token");
    expectError(serviceToken("card-service", ACCOUNT_SERVICE_SECRET), 401, "INVALID_CLIENT")
        .jsonPath("$.message")
        .isEqualTo("The client ID or the client secret is not correct.");
  }

  @Test
  void aUserCannotGetAServiceTokenWithItsPassword() {
    expectError(serviceToken(ADMIN, ADMIN_PASSWORD), 401, "INVALID_CLIENT");
  }

  @Test
  void aRequestWithMissingOrUnknownFieldsIsRejectedWithoutEchoingItsValues() {
    expectError(post("/api/v1/auth/login", Map.of("username", ADMIN)), 400, "INVALID_REQUEST")
        .jsonPath("$.message")
        .isEqualTo("Invalid or missing fields: password.");
    expectError(login("", "a-password-nobody-should-see"), 400, "INVALID_REQUEST")
        .jsonPath("$.message")
        .value(message -> assertThat(message.toString()).doesNotContain("nobody-should-see"));

    Map<String, Object> withExtraField = credentials(ADMIN, ADMIN_PASSWORD);
    withExtraField.put("role", "ADMIN");
    expectError(post("/api/v1/auth/login", withExtraField), 400, "INVALID_REQUEST");

    expectError(
        post("/api/v1/auth/service-token", Map.of("clientId", "account-service")),
        400,
        "INVALID_REQUEST");
  }

  @Test
  void aBodyThatIsNotJsonIsRejected() {
    expectError(
        webTestClient
            .post()
            .uri("/api/v1/auth/login")
            .contentType(MediaType.TEXT_PLAIN)
            .bodyValue("username=admin")
            .exchange(),
        415,
        "UNSUPPORTED_MEDIA_TYPE");
    expectError(
        webTestClient
            .post()
            .uri("/api/v1/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue("{not json")
            .exchange(),
        400,
        "INVALID_REQUEST");
  }

  @Test
  void anUnknownRouteAnswersWithTheErrorOfTheContract() {
    expectError(webTestClient.get().uri("/api/v1/auth/unknown").exchange(), 404, "NOT_FOUND");
  }
}
