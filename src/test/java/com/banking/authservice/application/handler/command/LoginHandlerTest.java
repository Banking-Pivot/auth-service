package com.banking.authservice.application.handler.command;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.banking.authservice.application.command.LoginCommand;
import com.banking.authservice.application.exception.InvalidCredentialsException;
import com.banking.authservice.application.port.out.PasswordHasherPort;
import com.banking.authservice.application.port.out.TokenSignerPort;
import com.banking.authservice.application.port.out.UserStorePort;
import com.banking.authservice.domain.model.AccessToken;
import com.banking.authservice.domain.model.Role;
import com.banking.authservice.domain.model.User;
import com.banking.authservice.domain.model.UserStatus;
import com.banking.authservice.support.Users;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

@ExtendWith(MockitoExtension.class)
class LoginHandlerTest {

  private static final AccessToken TOKEN = new AccessToken("a.b.c", 3600, Set.of(Role.USER));
  private static final int MAX_FAILED_ATTEMPTS = 3;
  private static final Duration LOCK = Duration.ofMinutes(15);
  private static final String PASSWORD = "the-password";
  private static final String WRONG_PASSWORD = "not-the-password";
  private static final String REFUSED = "The username or the password is not correct.";

  @Mock private UserStorePort users;
  @Mock private PasswordHasherPort hasher;
  @Mock private TokenSignerPort signer;

  private LoginHandler handler;

  @BeforeEach
  void setUp() {
    handler = new LoginHandler(users, hasher, signer, Users.CLOCK, MAX_FAILED_ATTEMPTS, LOCK);
  }

  @Test
  void aUserWithItsPasswordGetsATokenWithItsRoles() {
    User ana = Users.ana();
    when(users.findByUsername("ana")).thenReturn(Mono.just(ana));
    when(hasher.matches(PASSWORD, ana.passwordHash())).thenReturn(Mono.just(true));
    when(signer.sign("ana", Set.of(Role.USER))).thenReturn(Mono.just(TOKEN));

    AccessToken token = handler.execute(new LoginCommand("Ana", PASSWORD)).block();

    assertThat(token).isSameAs(TOKEN);
    verify(hasher, never()).hash(anyString());
    // No failed attempts to forget: a normal login writes nothing.
    verify(users, never()).updateLoginFailures(any(), any());
  }

  @Test
  void aWrongPasswordIsRefusedCountedAndNothingIsSigned() {
    User ana = Users.ana();
    User failedOnce = failed(ana, 1);
    when(users.findByUsername("ana")).thenReturn(Mono.just(ana));
    when(hasher.matches(WRONG_PASSWORD, ana.passwordHash())).thenReturn(Mono.just(false));
    when(users.updateLoginFailures(ana, failedOnce)).thenReturn(Mono.just(true));

    assertRefused("ana", WRONG_PASSWORD);

    verify(users).updateLoginFailures(ana, failedOnce);
    assertThat(failedOnce.lockedUntil()).isNull();
    verify(signer, never()).sign(any(), any());
  }

  @Test
  void theWrongPasswordThatReachesTheLimitLocksTheUser() {
    User failedTwice = failed(Users.ana(), 2);
    User locked = failed(Users.ana(), 3);
    when(users.findByUsername("ana")).thenReturn(Mono.just(failedTwice));
    when(hasher.matches(WRONG_PASSWORD, failedTwice.passwordHash())).thenReturn(Mono.just(false));
    when(users.updateLoginFailures(failedTwice, locked)).thenReturn(Mono.just(true));

    assertRefused("ana", WRONG_PASSWORD);

    assertThat(locked.failedAttempts()).isEqualTo(MAX_FAILED_ATTEMPTS);
    assertThat(locked.lockedUntil()).isEqualTo(Users.NOW.plus(LOCK));
    verify(users).updateLoginFailures(failedTwice, locked);
  }

  @Test
  void aLockedUserIsRefusedWithItsPasswordAfterCheckingItAndNothingIsStored() {
    User locked = failed(Users.ana(), 3);
    when(users.findByUsername("ana")).thenReturn(Mono.just(locked));
    when(hasher.matches(PASSWORD, locked.passwordHash())).thenReturn(Mono.just(true));

    assertRefused("ana", PASSWORD);

    // The password is checked all the same, so a locked user takes as long as a wrong password.
    verify(hasher).matches(PASSWORD, locked.passwordHash());
    verify(users, never()).updateLoginFailures(any(), any());
    verify(signer, never()).sign(any(), any());
  }

  @Test
  void aWrongPasswordWhileLockedIsNotCountedAndDoesNotExtendTheLock() {
    User locked = failed(Users.ana(), 3);
    when(users.findByUsername("ana")).thenReturn(Mono.just(locked));
    when(hasher.matches(WRONG_PASSWORD, locked.passwordHash())).thenReturn(Mono.just(false));

    assertRefused("ana", WRONG_PASSWORD);

    verify(hasher).matches(WRONG_PASSWORD, locked.passwordHash());
    verify(users, never()).updateLoginFailures(any(), any());
  }

  @Test
  void aCorrectLoginBeforeTheLimitForgetsTheFailedAttempts() {
    User failedTwice = failed(Users.ana(), 2);
    when(users.findByUsername("ana")).thenReturn(Mono.just(failedTwice));
    when(hasher.matches(PASSWORD, failedTwice.passwordHash())).thenReturn(Mono.just(true));
    when(users.updateLoginFailures(failedTwice, Users.ana())).thenReturn(Mono.just(true));
    when(signer.sign("ana", Set.of(Role.USER))).thenReturn(Mono.just(TOKEN));

    assertThat(handler.execute(new LoginCommand("ana", PASSWORD)).block()).isSameAs(TOKEN);

    verify(users).updateLoginFailures(failedTwice, Users.ana());
  }

  @Test
  void whenTheLockHasEndedTheUserLogsInAndTheCountIsForgotten() {
    User lockEnded = lockedAt(Users.NOW.minus(LOCK));
    when(users.findByUsername("ana")).thenReturn(Mono.just(lockEnded));
    when(hasher.matches(PASSWORD, lockEnded.passwordHash())).thenReturn(Mono.just(true));
    when(users.updateLoginFailures(lockEnded, Users.ana())).thenReturn(Mono.just(true));
    when(signer.sign("ana", Set.of(Role.USER))).thenReturn(Mono.just(TOKEN));

    assertThat(handler.execute(new LoginCommand("ana", PASSWORD)).block()).isSameAs(TOKEN);
  }

  @Test
  void whenTheLockHasEndedAWrongPasswordStartsTheCountAgain() {
    User lockEnded = lockedAt(Users.NOW.minus(LOCK).minusSeconds(1));
    User failedOnce = failed(Users.ana(), 1);
    when(users.findByUsername("ana")).thenReturn(Mono.just(lockEnded));
    when(hasher.matches(WRONG_PASSWORD, lockEnded.passwordHash())).thenReturn(Mono.just(false));
    when(users.updateLoginFailures(lockEnded, failedOnce)).thenReturn(Mono.just(true));

    assertRefused("ana", WRONG_PASSWORD);

    verify(users).updateLoginFailures(lockEnded, failedOnce);
  }

  @Test
  void aWrongPasswordThatLosesTheRaceIsCountedOnTopOfTheOneThatWon() {
    User ana = Users.ana();
    User failedOnce = failed(ana, 1);
    User failedTwice = failed(ana, 2);
    when(users.findByUsername("ana")).thenReturn(Mono.just(ana));
    when(hasher.matches(WRONG_PASSWORD, ana.passwordHash())).thenReturn(Mono.just(false));
    // Another login of ana stored its failed attempt first.
    when(users.updateLoginFailures(ana, failedOnce)).thenReturn(Mono.just(false));
    when(users.findById(Users.ANA_ID)).thenReturn(Mono.just(failedOnce));
    when(users.updateLoginFailures(failedOnce, failedTwice)).thenReturn(Mono.just(true));

    assertRefused("ana", WRONG_PASSWORD);

    verify(users).updateLoginFailures(failedOnce, failedTwice);
    // The password is not checked again: only what is stored is read again.
    verify(hasher, times(1)).matches(anyString(), anyString());
  }

  @Test
  void aCorrectLoginThatLosesTheRaceToTheLockIsRefused() {
    User failedTwice = failed(Users.ana(), 2);
    when(users.findByUsername("ana")).thenReturn(Mono.just(failedTwice));
    when(hasher.matches(PASSWORD, failedTwice.passwordHash())).thenReturn(Mono.just(true));
    // A wrong password got there first and locked the user.
    when(users.updateLoginFailures(failedTwice, Users.ana())).thenReturn(Mono.just(false));
    when(users.findById(Users.ANA_ID)).thenReturn(Mono.just(failed(Users.ana(), 3)));

    assertRefused("ana", PASSWORD);

    verify(signer, never()).sign(any(), any());
  }

  @Test
  void aLoginThatLosesTheRaceAndFindsNoUserAnyMoreIsRefused() {
    User ana = Users.ana();
    when(users.findByUsername("ana")).thenReturn(Mono.just(ana));
    when(hasher.matches(WRONG_PASSWORD, ana.passwordHash())).thenReturn(Mono.just(false));
    when(users.updateLoginFailures(any(), any())).thenReturn(Mono.just(false));
    when(users.findById(Users.ANA_ID)).thenReturn(Mono.empty());

    assertRefused("ana", WRONG_PASSWORD);
  }

  @Test
  void aDisabledUserIsRefusedEvenWithItsPassword() {
    User disabled = Users.ana().withStatus(UserStatus.DISABLED, Users.NOW);
    when(users.findByUsername("ana")).thenReturn(Mono.just(disabled));
    when(hasher.matches(PASSWORD, disabled.passwordHash())).thenReturn(Mono.just(true));

    assertRefused("ana", PASSWORD);

    verify(signer, never()).sign(any(), any());
    verify(users, never()).updateLoginFailures(any(), any());
  }

  @Test
  void aDisabledUserWithFailedAttemptsKeepsThemWhenItsPasswordIsRight() {
    User disabled = failed(Users.ana(), 2).withStatus(UserStatus.DISABLED, Users.NOW);
    when(users.findByUsername("ana")).thenReturn(Mono.just(disabled));
    when(hasher.matches(PASSWORD, disabled.passwordHash())).thenReturn(Mono.just(true));

    assertRefused("ana", PASSWORD);

    verify(users, never()).updateLoginFailures(any(), any());
  }

  @Test
  void anUnknownUserIsRefusedAfterCheckingThePasswordAgainstADecoyHash() {
    when(users.findByUsername("nobody")).thenReturn(Mono.empty());
    when(hasher.hash(anyString())).thenReturn(Mono.just("decoy-hash"));
    // Even a hasher that says yes does not let an unknown user in.
    when(hasher.matches("any-password", "decoy-hash")).thenReturn(Mono.just(true));

    assertRefused("nobody", "any-password");

    verify(hasher).matches("any-password", "decoy-hash");
    verify(signer, never()).sign(any(), any());
    // Nothing is counted for a name that is not a user.
    verify(users, never()).updateLoginFailures(any(), any());
    verify(users, never()).insert(any());
  }

  @Test
  void theDecoyHashIsMadeOnce() {
    when(users.findByUsername("nobody")).thenReturn(Mono.empty());
    when(hasher.hash(anyString())).thenReturn(Mono.just("decoy-hash"));
    when(hasher.matches("any-password", "decoy-hash")).thenReturn(Mono.just(false));
    LoginCommand command = new LoginCommand("nobody", "any-password");

    assertThatThrownBy(() -> handler.execute(command).block())
        .isInstanceOf(InvalidCredentialsException.class);
    assertThatThrownBy(() -> handler.execute(command).block())
        .isInstanceOf(InvalidCredentialsException.class);

    verify(hasher, times(1)).hash(anyString());
    assertThat(command.toString()).contains("nobody").doesNotContain("any-password");
  }

  private void assertRefused(String username, String password) {
    LoginCommand command = new LoginCommand(username, password);
    assertThatThrownBy(() -> handler.execute(command).block())
        .isInstanceOf(InvalidCredentialsException.class)
        .hasMessage(REFUSED);
  }

  /** The user after that many wrong passwords in a row at the instant of the test clock. */
  private static User failed(User user, int times) {
    User failed = user;
    for (int attempt = 0; attempt < times; attempt++) {
      failed = failed.withFailedLogin(MAX_FAILED_ATTEMPTS, LOCK, Users.NOW);
    }
    return failed;
  }

  /** Ana, locked by a wrong password at that instant. */
  private static User lockedAt(Instant instant) {
    return Users.ana().withFailedLogin(1, LOCK, instant);
  }
}
