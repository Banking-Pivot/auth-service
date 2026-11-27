package com.banking.authservice.infrastructure.adapter.in.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

import com.banking.authservice.application.port.out.UserStorePort;
import com.banking.authservice.domain.model.User;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.UserResponse;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.UserStatus;
import com.banking.authservice.support.IntegrationTest;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * The lock after wrong passwords, end to end against a real database. The settings of the tests
 * lock a user after 3 wrong passwords for 10 minutes.
 */
class LoginLockApiTest extends IntegrationTest {

  private static final String WRONG_PASSWORD = "not-the-password";
  private static final String REFUSED = "The username or the password is not correct.";
  private static final Duration LOCK = Duration.ofMinutes(10);

  @Autowired private UserStorePort users;

  @Test
  void theConfiguredNumberOfWrongPasswordsLocksTheUserAndItsPasswordIsRefusedToo() {
    UserResponse ana = created("ana", "USER");

    refused("ana", WRONG_PASSWORD);
    refused("ana", WRONG_PASSWORD);
    assertThat(read(ana.getId()).getFailedAttempts()).isEqualTo(2);
    assertThat(read(ana.getId()).getLockedUntil()).isNull();
    refused("ana", WRONG_PASSWORD);

    // The same answer as a wrong password: nothing tells that the user is locked.
    refused("ana", PASSWORD);
    refused("ANA", PASSWORD);

    UserResponse locked = read(ana.getId());
    assertThat(locked.getFailedAttempts()).isEqualTo(3);
    assertThat(locked.getLockedUntil())
        .isCloseTo(OffsetDateTime.now().plus(LOCK), within(1, ChronoUnit.MINUTES));
    assertThat(locked.getStatus()).isEqualTo(UserStatus.ACTIVE);
    assertThat(locked.getUpdatedAt()).isEqualTo(ana.getUpdatedAt());
  }

  @Test
  void aNewUserHasNoFailedAttemptsAndNoLockInItsAnswer() {
    createUser(newUser("ana", "USER"))
        .expectStatus()
        .isCreated()
        .expectBody()
        .jsonPath("$.failedAttempts")
        .isEqualTo(0)
        .jsonPath("$.lockedUntil")
        .doesNotExist();
  }

  @Test
  void aCorrectLoginBeforeTheLimitStartsTheCountAgain() {
    UserResponse ana = created("ana", "USER");

    refused("ana", WRONG_PASSWORD);
    refused("ana", WRONG_PASSWORD);
    loggedIn("ana", PASSWORD);
    assertThat(read(ana.getId()).getFailedAttempts()).isZero();

    // Two more do not lock: the count started again.
    refused("ana", WRONG_PASSWORD);
    refused("ana", WRONG_PASSWORD);
    loggedIn("ana", PASSWORD);
  }

  @Test
  void whileLockedNothingIsCountedAndTheLockIsNotExtended() {
    UserResponse ana = created("ana", "USER");
    lock("ana");
    UserResponse locked = read(ana.getId());

    refused("ana", WRONG_PASSWORD);
    refused("ana", PASSWORD);

    assertThat(read(ana.getId())).isEqualTo(locked);
  }

  @Test
  void whenTheLockEndsTheUserLogsInAgainAndTheCountIsForgotten() {
    UserResponse ana = created("ana", "USER");
    lock("ana");
    endTheLockOf("ana");

    loggedIn("ana", PASSWORD);

    UserResponse afterLogin = read(ana.getId());
    assertThat(afterLogin.getFailedAttempts()).isZero();
    assertThat(afterLogin.getLockedUntil()).isNull();
  }

  @Test
  void whenTheLockEndsAWrongPasswordStartsTheCountAtOne() {
    UserResponse ana = created("ana", "USER");
    lock("ana");
    endTheLockOf("ana");

    refused("ana", WRONG_PASSWORD);

    UserResponse failedOnce = read(ana.getId());
    assertThat(failedOnce.getFailedAttempts()).isEqualTo(1);
    assertThat(failedOnce.getLockedUntil()).isNull();
    loggedIn("ana", PASSWORD);
  }

  @Test
  void anAdministratorUnlocksAUserAndUnlockingAgainChangesNothing() {
    UserResponse ana = created("ana", "USER");
    lock("ana");

    userAction(ana.getId(), "unlock")
        .expectStatus()
        .isOk()
        .expectBody()
        .jsonPath("$.id")
        .isEqualTo(ana.getId().toString())
        .jsonPath("$.failedAttempts")
        .isEqualTo(0)
        .jsonPath("$.lockedUntil")
        .doesNotExist()
        .jsonPath("$.status")
        .isEqualTo("ACTIVE");
    UserResponse unlocked = read(ana.getId());

    assertThat(unlocked.getFailedAttempts()).isZero();
    assertThat(unlocked.getLockedUntil()).isNull();
    assertThat(unlocked.getUpdatedAt()).isEqualTo(ana.getUpdatedAt());
    assertThat(changed(ana.getId(), "unlock")).isEqualTo(unlocked);
    loggedIn("ana", PASSWORD);
  }

  @Test
  void unlockingForgetsFailedAttemptsThatHaveNotLockedYet() {
    UserResponse ana = created("ana", "USER");
    refused("ana", WRONG_PASSWORD);
    refused("ana", WRONG_PASSWORD);

    assertThat(changed(ana.getId(), "unlock").getFailedAttempts()).isZero();

    // Two more wrong passwords do not lock after the unlock.
    refused("ana", WRONG_PASSWORD);
    refused("ana", WRONG_PASSWORD);
    loggedIn("ana", PASSWORD);
  }

  @Test
  void unlockingADisabledUserLeavesItDisabled() {
    UserResponse ana = created("ana", "USER");
    lock("ana");
    changed(ana.getId(), "disable");

    UserResponse unlocked = changed(ana.getId(), "unlock");

    assertThat(unlocked.getStatus()).isEqualTo(UserStatus.DISABLED);
    assertThat(unlocked.getFailedAttempts()).isZero();
    refused("ana", PASSWORD);
  }

  @Test
  void unlockingAnUnknownUserIsNotFound() {
    UUID unknown = UUID.randomUUID();

    expectError(userAction(unknown, "unlock"), 404, "USER_NOT_FOUND")
        .jsonPath("$.path")
        .isEqualTo("/api/v1/auth/users/" + unknown + "/unlock");
    expectError(
        webTestClient.post().uri("/api/v1/auth/users/not-a-uuid/unlock").exchange(),
        400,
        "INVALID_REQUEST");
  }

  @Test
  void enablingAUserEndsItsLockAlsoWhenItWasNotDisabled() {
    UserResponse ana = created("ana", "USER");
    lock("ana");

    UserResponse enabled = changed(ana.getId(), "enable");

    assertThat(enabled.getFailedAttempts()).isZero();
    assertThat(enabled.getLockedUntil()).isNull();
    assertThat(enabled.getUpdatedAt()).isEqualTo(ana.getUpdatedAt());
    assertThat(read(ana.getId())).isEqualTo(enabled);
    loggedIn("ana", PASSWORD);
  }

  @Test
  void enablingADisabledUserThatWasLockedLetsItLogInAtOnce() {
    UserResponse ana = created("ana", "USER");
    lock("ana");
    UserResponse disabled = changed(ana.getId(), "disable");
    assertThat(disabled.getFailedAttempts()).isEqualTo(3);

    UserResponse enabled = changed(ana.getId(), "enable");

    assertThat(enabled.getStatus()).isEqualTo(UserStatus.ACTIVE);
    assertThat(enabled.getFailedAttempts()).isZero();
    assertThat(enabled.getLockedUntil()).isNull();
    loggedIn("ana", PASSWORD);
  }

  @Test
  void theFirstAdministratorIsLockedLikeAnyOtherUser() {
    lock(ADMIN);

    refused(ADMIN, ADMIN_PASSWORD);

    UUID admin = userId(ADMIN);
    assertThat(read(admin).getFailedAttempts()).isEqualTo(3);
    changed(admin, "unlock");
    loggedIn(ADMIN, ADMIN_PASSWORD);
  }

  @Test
  void aNameThatIsNotAUserIsNeverCountedNorStored() {
    for (int attempt = 0; attempt < 5; attempt++) {
      refused("nobody", WRONG_PASSWORD);
    }

    assertThat(count("SELECT count(*) FROM users")).isEqualTo(1);
    // The name can still be taken, and the new user starts clean.
    assertThat(created("nobody", "USER").getFailedAttempts()).isZero();
    loggedIn("nobody", PASSWORD);
  }

  @Test
  void wrongSecretsNeverLockAServiceClient() {
    for (int attempt = 0; attempt < 5; attempt++) {
      expectError(serviceToken("account-service", "not-the-secret"), 401, "INVALID_CLIENT");
    }

    serviceToken("account-service", ACCOUNT_SERVICE_SECRET).expectStatus().isOk();
    assertThat(count("SELECT count(*) FROM users WHERE failed_attempts > 0")).isZero();
  }

  @Test
  void wrongPasswordsAtTheSameTimeAreAllCounted() {
    UserResponse ana = created("ana", "USER");

    for (int round = 0; round < 5; round++) {
      assertThat(statusesOfLoginsAtTheSameTime("ana", WRONG_PASSWORD, 2)).containsOnly(401);

      assertThat(read(ana.getId()).getFailedAttempts()).as("round %d", round).isEqualTo(2);
      changed(ana.getId(), "unlock");
    }
  }

  @Test
  void manyWrongPasswordsAtTheSameTimeLockTheUserAtTheLimitAndNoFurther() {
    UserResponse ana = created("ana", "USER");

    assertThat(statusesOfLoginsAtTheSameTime("ana", WRONG_PASSWORD, 12)).containsOnly(401);

    UserResponse locked = read(ana.getId());
    assertThat(locked.getFailedAttempts()).isEqualTo(3);
    assertThat(locked.getLockedUntil()).isNotNull();
    refused("ana", PASSWORD);
  }

  @Test
  void ofTwoWritesThatReadTheSameCountOnlyOneIsStored() {
    created("ana", "USER");
    User read = users.findByUsername("ana").block();
    User failed = read.withFailedLogin(3, LOCK, Instant.now());

    List<Boolean> stored =
        Flux.range(0, 8)
            .flatMap(attempt -> users.updateLoginFailures(read, failed), 8)
            .collectList()
            .block();

    assertThat(stored).filteredOn(Boolean.TRUE::equals).hasSize(1);
    assertThat(users.findByUsername("ana").block().failedAttempts()).isEqualTo(1);
  }

  @Test
  void aWriteOnlyGoesThroughWhileTheLockIsTheOneThatWasRead() {
    created("ana", "USER");
    User read = users.findByUsername("ana").block();
    User locked = read.withFailedLogin(1, LOCK, Instant.now());
    assertThat(users.updateLoginFailures(read, locked).block()).isTrue();
    assertThat(users.findByUsername("ana").block()).isEqualTo(locked);

    // The same count and another lock: not the user that was read.
    User otherLock = read.withFailedLogin(1, LOCK, Instant.now().plusSeconds(60));
    assertThat(users.updateLoginFailures(otherLock, read).block()).isFalse();
    assertThat(users.updateLoginFailures(read, otherLock).block()).isFalse();
    assertThat(users.updateLoginFailures(locked, read).block()).isTrue();
    assertThat(users.findByUsername("ana").block()).isEqualTo(read);

    users.updateLoginFailures(read, locked).block();
    users.clearLoginFailures(read.id()).block();
    assertThat(users.findByUsername("ana").block()).isEqualTo(read);
  }

  // ----- helpers

  private void refused(String username, String password) {
    expectError(login(username, password), 401, "INVALID_CREDENTIALS")
        .jsonPath("$.message")
        .isEqualTo(REFUSED)
        .jsonPath("$.path")
        .isEqualTo("/api/v1/auth/login")
        .jsonPath("$.length()")
        .isEqualTo(5);
  }

  /** Three wrong passwords: the limit of the test settings. */
  private void lock(String username) {
    for (int attempt = 0; attempt < 3; attempt++) {
      refused(username, WRONG_PASSWORD);
    }
  }

  /** Moves the end of the lock to the past, as if its duration had gone by. */
  private void endTheLockOf(String username) {
    databaseClient
        .sql("UPDATE users SET locked_until = now() - INTERVAL '1 second' WHERE username = :name")
        .bind("name", username)
        .then()
        .block();
  }

  private List<Integer> statusesOfLoginsAtTheSameTime(String username, String password, int count) {
    return Flux.range(0, count)
        .flatMap(
            attempt ->
                Mono.fromCallable(
                        () -> login(username, password).returnResult(String.class).getStatus())
                    .map(status -> status.value())
                    .subscribeOn(Schedulers.boundedElastic()),
            count)
        .collectList()
        .block();
  }

  private UserResponse read(UUID userId) {
    return webTestClient
        .get()
        .uri("/api/v1/auth/users/{userId}", userId)
        .exchange()
        .expectStatus()
        .isOk()
        .expectBody(UserResponse.class)
        .returnResult()
        .getResponseBody();
  }

  private UserResponse changed(UUID userId, String action) {
    return userAction(userId, action)
        .expectStatus()
        .isOk()
        .expectBody(UserResponse.class)
        .returnResult()
        .getResponseBody();
  }

  private UUID userId(String username) {
    return databaseClient
        .sql("SELECT id FROM users WHERE username = :username")
        .bind("username", username)
        .map(row -> row.get(0, UUID.class))
        .one()
        .block();
  }

  private long count(String sql) {
    return databaseClient.sql(sql).map(row -> row.get(0, Long.class)).one().block();
  }
}
