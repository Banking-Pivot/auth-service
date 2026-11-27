package com.banking.authservice.application.handler.command;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.banking.authservice.application.exception.UserNotFoundException;
import com.banking.authservice.application.port.out.UserStorePort;
import com.banking.authservice.domain.model.User;
import com.banking.authservice.domain.model.enums.UserStatus;
import com.banking.authservice.support.Users;
import java.time.Duration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

@ExtendWith(MockitoExtension.class)
class UnlockUserHandlerTest {

  private static final Duration LOCK = Duration.ofMinutes(15);

  @Mock private UserStorePort users;

  private UnlockUserHandler handler;

  @BeforeEach
  void setUp() {
    handler = new UnlockUserHandler(users);
  }

  @Test
  void unlockingALockedUserForgetsItsFailedAttemptsAndItsLock() {
    User locked = Users.ana().withFailedLogin(1, LOCK, Users.NOW);
    when(users.findById(Users.ANA_ID)).thenReturn(Mono.just(locked));
    when(users.clearLoginFailures(Users.ANA_ID)).thenReturn(Mono.empty());

    User unlocked = handler.execute(Users.ANA_ID).block();

    assertThat(unlocked).isEqualTo(Users.ana());
    verify(users).clearLoginFailures(Users.ANA_ID);
  }

  @Test
  void unlockingAUserWithFailedAttemptsThatIsNotLockedYetForgetsThem() {
    User failed = Users.ana().withFailedLogin(3, LOCK, Users.NOW);
    when(users.findById(Users.ANA_ID)).thenReturn(Mono.just(failed));
    when(users.clearLoginFailures(Users.ANA_ID)).thenReturn(Mono.empty());

    assertThat(handler.execute(Users.ANA_ID).block().failedAttempts()).isZero();
  }

  @Test
  void unlockingAUserThatHasNothingToForgetStoresNothing() {
    User ana = Users.ana();
    when(users.findById(Users.ANA_ID)).thenReturn(Mono.just(ana));

    assertThat(handler.execute(Users.ANA_ID).block()).isSameAs(ana);
    verify(users, never()).clearLoginFailures(any());
  }

  @Test
  void unlockingADisabledUserLeavesItDisabled() {
    User locked =
        Users.ana().withFailedLogin(1, LOCK, Users.NOW).withStatus(UserStatus.DISABLED, Users.NOW);
    when(users.findById(Users.ANA_ID)).thenReturn(Mono.just(locked));
    when(users.clearLoginFailures(Users.ANA_ID)).thenReturn(Mono.empty());

    User unlocked = handler.execute(Users.ANA_ID).block();

    assertThat(unlocked.isActive()).isFalse();
    assertThat(unlocked.hasLoginFailures()).isFalse();
    verify(users, never()).updateStatus(any());
  }

  @Test
  void anUnknownUserIsNotFound() {
    when(users.findById(Users.ANA_ID)).thenReturn(Mono.empty());

    assertThatThrownBy(() -> handler.execute(Users.ANA_ID).block())
        .isInstanceOf(UserNotFoundException.class)
        .hasMessageContaining(Users.ANA_ID.toString());
    verify(users, never()).clearLoginFailures(any());
  }
}
