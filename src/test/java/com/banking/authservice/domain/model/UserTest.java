package com.banking.authservice.domain.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.banking.authservice.domain.model.enums.Role;
import com.banking.authservice.domain.model.enums.UserStatus;
import com.banking.authservice.domain.model.vo.AccessToken;
import com.banking.authservice.support.Users;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class UserTest {

  private static final Duration LOCK = Duration.ofMinutes(15);

  @Test
  void aNewUserIsActiveAndItsNameIsStoredInLowerCase() {
    User user =
        User.register(Users.ANA_ID, "Ana.Perez", "hash", Set.of(Role.USER, Role.ADMIN), Users.NOW);

    assertThat(user.username()).isEqualTo("ana.perez");
    assertThat(user.isActive()).isTrue();
    assertThat(user.isAdministrator()).isTrue();
    assertThat(user.createdAt()).isEqualTo(Users.NOW).isEqualTo(user.updatedAt());
    assertThat(User.normalize(null)).isNull();
  }

  @ParameterizedTest
  @ValueSource(strings = {"ab", "-ana", "ana perez", "ana@bank", "añá"})
  void aNameWithOtherCharactersOrTooShortIsRejected(String username) {
    assertThatThrownBy(() -> User.register(Users.ANA_ID, username, "hash", roles(), Users.NOW))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> User.register(Users.ANA_ID, null, "hash", roles(), Users.NOW))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () -> User.register(Users.ANA_ID, "a".repeat(51), "hash", roles(), Users.NOW))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void aUserNeedsARoleAndCannotHaveTheOneOfServices() {
    assertThatThrownBy(() -> User.register(Users.ANA_ID, "ana", "hash", Set.of(), Users.NOW))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("at least one role");
    assertThatThrownBy(() -> User.register(Users.ANA_ID, "ana", "hash", null, Users.NOW))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () ->
                User.register(
                    Users.ANA_ID, "ana", "hash", Set.of(Role.USER, Role.SERVICE), Users.NOW))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("reserved for services");
    assertThat(Role.SERVICE.assignableToUsers()).isFalse();
  }

  @Test
  void disablingAndEnablingKeepEverythingElse() {
    User ana = Users.ana();

    User disabled = ana.withStatus(UserStatus.DISABLED, Users.NOW);

    assertThat(disabled.isActive()).isFalse();
    assertThat(disabled.updatedAt()).isEqualTo(Users.NOW);
    assertThat(disabled.createdAt()).isEqualTo(ana.createdAt());
    assertThat(disabled.passwordHash()).isEqualTo(ana.passwordHash());
    assertThat(disabled.withStatus(UserStatus.DISABLED, Users.NOW.plusSeconds(5)))
        .isSameAs(disabled);
    assertThat(disabled.withStatus(UserStatus.ACTIVE, Users.NOW.plusSeconds(5)).isActive())
        .isTrue();
  }

  @Test
  void aNewUserHasNoFailedAttemptsAndIsNotLocked() {
    User ana = Users.ana();

    assertThat(ana.failedAttempts()).isZero();
    assertThat(ana.lockedUntil()).isNull();
    assertThat(ana.hasLoginFailures()).isFalse();
    assertThat(ana.isLockedAt(Users.NOW)).isFalse();
    assertThat(ana.withoutLoginFailures()).isSameAs(ana);
  }

  @Test
  void wrongPasswordsAreCountedAndTheOneThatReachesTheLimitLocksTheUser() {
    User once = Users.ana().withFailedLogin(3, LOCK, Users.NOW);
    User twice = once.withFailedLogin(3, LOCK, Users.NOW);
    User locked = twice.withFailedLogin(3, LOCK, Users.NOW);

    assertThat(once.failedAttempts()).isEqualTo(1);
    assertThat(once.hasLoginFailures()).isTrue();
    assertThat(twice.failedAttempts()).isEqualTo(2);
    assertThat(twice.lockedUntil()).isNull();
    assertThat(twice.isLockedAt(Users.NOW)).isFalse();
    assertThat(locked.failedAttempts()).isEqualTo(3);
    assertThat(locked.lockedUntil()).isEqualTo(Users.NOW.plus(LOCK));
    // Nothing else changes: not the status and not when it was last enabled or disabled.
    assertThat(locked.isActive()).isTrue();
    assertThat(locked.updatedAt()).isEqualTo(Users.ana().updatedAt());
    assertThat(locked.passwordHash()).isEqualTo(Users.ana().passwordHash());
  }

  @Test
  void aUserIsLockedUntilTheLockEndsAndNotAfter() {
    User locked = Users.ana().withFailedLogin(1, LOCK, Users.NOW);
    Instant end = Users.NOW.plus(LOCK);

    assertThat(locked.isLockedAt(Users.NOW)).isTrue();
    assertThat(locked.isLockedAt(end.minusMillis(1))).isTrue();
    assertThat(locked.isLockedAt(end)).isFalse();
    assertThat(locked.isLockedAt(end.plusSeconds(1))).isFalse();
  }

  @Test
  void afterALockTheCountStartsAgain() {
    User locked = Users.ana().withFailedLogin(1, LOCK, Users.NOW);

    User failedAgain = locked.withFailedLogin(3, LOCK, Users.NOW.plus(LOCK).plusSeconds(1));

    assertThat(failedAgain.failedAttempts()).isEqualTo(1);
    assertThat(failedAgain.lockedUntil()).isNull();
  }

  @Test
  void forgettingTheFailuresLeavesNoCountAndNoLock() {
    User locked = Users.ana().withFailedLogin(1, LOCK, Users.NOW);

    User cleared = locked.withoutLoginFailures();

    assertThat(cleared).isEqualTo(Users.ana());
    assertThat(Users.ana().withFailedLogin(3, LOCK, Users.NOW).withoutLoginFailures())
        .isEqualTo(Users.ana());
  }

  @Test
  void disablingAndEnablingKeepTheFailedAttemptsAndTheLock() {
    User locked = Users.ana().withFailedLogin(1, LOCK, Users.NOW);

    User disabled = locked.withStatus(UserStatus.DISABLED, Users.NOW);

    assertThat(disabled.failedAttempts()).isEqualTo(1);
    assertThat(disabled.lockedUntil()).isEqualTo(locked.lockedUntil());
  }

  @Test
  void aNegativeCountIsRejectedAndTheLockIsKeptToTheMicrosecond() {
    User ana = Users.ana();

    assertThatThrownBy(
            () ->
                new User(
                    ana.id(),
                    ana.username(),
                    ana.passwordHash(),
                    ana.roles(),
                    ana.status(),
                    -1,
                    null,
                    ana.createdAt(),
                    ana.updatedAt()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("failedAttempts");
    assertThat(
            ana.withFailedLogin(1, LOCK, Instant.parse("2026-11-20T15:00:00.123456789Z"))
                .lockedUntil())
        .isEqualTo(Instant.parse("2026-11-20T15:15:00.123456Z"));
  }

  @Test
  void instantsAreKeptToTheMicrosecondLikeTheDatabaseDoes() {
    User user =
        User.register(
            Users.ANA_ID, "ana", "hash", roles(), Instant.parse("2026-11-20T15:00:00.123456789Z"));

    assertThat(user.createdAt())
        .isEqualTo(Instant.parse("2026-11-20T15:00:00.123456Z"))
        .isEqualTo(user.updatedAt());
  }

  @Test
  void theRolesOfAUserCannotBeChangedFromOutside() {
    User ana = Users.ana();

    assertThatThrownBy(() -> ana.roles().add(Role.ADMIN))
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void theTextOfAUserOrOfATokenNeverShowsTheHashOrTheToken() {
    User user = User.register(UUID.randomUUID(), "ana", "hash-of-ana", roles(), Users.NOW);
    AccessToken token = new AccessToken("header.payload.signature", 900, roles());

    assertThat(user.toString()).contains("ana").doesNotContain("hash-of-ana");
    assertThat(token.toString()).contains("900").doesNotContain("payload");
    assertThatThrownBy(() -> new AccessToken(null, 900, roles()))
        .isInstanceOf(NullPointerException.class);
  }

  private static Set<Role> roles() {
    return Set.of(Role.USER);
  }
}
