package com.banking.authservice.application.handler.command;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.banking.authservice.application.exception.UserNotFoundException;
import com.banking.authservice.application.port.out.UserStorePort;
import com.banking.authservice.domain.exception.AuthRuleViolationException;
import com.banking.authservice.domain.exception.RuleViolation;
import com.banking.authservice.domain.model.User;
import com.banking.authservice.domain.model.UserStatus;
import com.banking.authservice.support.Users;
import java.time.Duration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

@ExtendWith(MockitoExtension.class)
class ChangeUserStatusHandlerTest {

  @Mock private UserStorePort users;

  private ChangeUserStatusHandler handler;

  @BeforeEach
  void setUp() {
    handler = new ChangeUserStatusHandler(users, Users.CLOCK);
  }

  @Test
  void disablingAUserStoresItsNewStatusAndWhenItChanged() {
    when(users.findById(Users.ANA_ID)).thenReturn(Mono.just(Users.ana()));
    when(users.updateStatus(any())).thenReturn(Mono.empty());

    User disabled = handler.disable(Users.ANA_ID).block();

    assertThat(disabled.status()).isEqualTo(UserStatus.DISABLED);
    assertThat(disabled.updatedAt()).isEqualTo(Users.NOW);
    verify(users).updateStatus(disabled);
    // Not an administrator: nobody counts administrators.
    verify(users, never()).countActiveAdministrators();
  }

  @Test
  void disablingAUserAlreadyDisabledChangesNothing() {
    User disabled = Users.ana().withStatus(UserStatus.DISABLED, Users.NOW.minusSeconds(60));
    when(users.findById(Users.ANA_ID)).thenReturn(Mono.just(disabled));

    assertThat(handler.disable(Users.ANA_ID).block()).isSameAs(disabled);
    verify(users, never()).updateStatus(any());
  }

  @Test
  void theLastEnabledAdministratorCannotBeDisabled() {
    when(users.findById(Users.ADMIN_ID)).thenReturn(Mono.just(Users.admin()));
    when(users.countActiveAdministrators()).thenReturn(Mono.just(1L));

    assertThatThrownBy(() -> handler.disable(Users.ADMIN_ID).block())
        .isInstanceOfSatisfying(
            AuthRuleViolationException.class,
            error -> assertThat(error.violation()).isEqualTo(RuleViolation.LAST_ACTIVE_ADMIN))
        .hasMessage("The last enabled administrator cannot be disabled.");
    verify(users, never()).updateStatus(any());
  }

  @Test
  void anAdministratorCanBeDisabledWhileAnotherOneCanLogIn() {
    when(users.findById(Users.ADMIN_ID)).thenReturn(Mono.just(Users.admin()));
    when(users.countActiveAdministrators()).thenReturn(Mono.just(2L));
    when(users.updateStatus(any())).thenReturn(Mono.empty());

    assertThat(handler.disable(Users.ADMIN_ID).block().isActive()).isFalse();
  }

  @Test
  void enablingADisabledUserStoresItAndEnablingAnEnabledOneChangesNothing() {
    User disabled = Users.ana().withStatus(UserStatus.DISABLED, Users.NOW.minusSeconds(60));
    when(users.findById(Users.ANA_ID)).thenReturn(Mono.just(disabled), Mono.just(Users.ana()));
    when(users.updateStatus(any())).thenReturn(Mono.empty());

    User enabled = handler.enable(Users.ANA_ID).block();
    User unchanged = handler.enable(Users.ANA_ID).block();

    assertThat(enabled.isActive()).isTrue();
    assertThat(enabled.updatedAt()).isEqualTo(Users.NOW);
    assertThat(unchanged.updatedAt()).isEqualTo(Users.ana().updatedAt());
    verify(users).updateStatus(enabled);
    // Neither of them had failed attempts: there is nothing to forget.
    verify(users, never()).clearLoginFailures(any());
  }

  @Test
  void enablingADisabledUserThatIsLockedAlsoForgetsItsFailedAttemptsAndItsLock() {
    User locked =
        Users.ana()
            .withFailedLogin(1, Duration.ofMinutes(15), Users.NOW)
            .withStatus(UserStatus.DISABLED, Users.NOW.minusSeconds(60));
    when(users.findById(Users.ANA_ID)).thenReturn(Mono.just(locked));
    when(users.updateStatus(any())).thenReturn(Mono.empty());
    when(users.clearLoginFailures(Users.ANA_ID)).thenReturn(Mono.empty());

    User enabled = handler.enable(Users.ANA_ID).block();

    assertThat(enabled.isActive()).isTrue();
    assertThat(enabled.failedAttempts()).isZero();
    assertThat(enabled.lockedUntil()).isNull();
    verify(users).updateStatus(any());
    verify(users).clearLoginFailures(Users.ANA_ID);
  }

  @Test
  void enablingAnEnabledUserThatIsLockedOnlyForgetsItsFailedAttemptsAndItsLock() {
    User locked = Users.ana().withFailedLogin(1, Duration.ofMinutes(15), Users.NOW);
    when(users.findById(Users.ANA_ID)).thenReturn(Mono.just(locked));
    when(users.clearLoginFailures(Users.ANA_ID)).thenReturn(Mono.empty());

    User enabled = handler.enable(Users.ANA_ID).block();

    assertThat(enabled).isEqualTo(Users.ana());
    verify(users, never()).updateStatus(any());
    verify(users).clearLoginFailures(Users.ANA_ID);
  }

  @Test
  void disablingALockedUserKeepsItsFailedAttemptsAndItsLock() {
    User locked = Users.ana().withFailedLogin(1, Duration.ofMinutes(15), Users.NOW);
    when(users.findById(Users.ANA_ID)).thenReturn(Mono.just(locked));
    when(users.updateStatus(any())).thenReturn(Mono.empty());

    User disabled = handler.disable(Users.ANA_ID).block();

    assertThat(disabled.failedAttempts()).isEqualTo(1);
    assertThat(disabled.lockedUntil()).isEqualTo(locked.lockedUntil());
    verify(users, never()).clearLoginFailures(any());
  }

  @Test
  void anUnknownUserIsNotFound() {
    when(users.findById(Users.ANA_ID)).thenReturn(Mono.empty());

    assertThatThrownBy(() -> handler.disable(Users.ANA_ID).block())
        .isInstanceOf(UserNotFoundException.class)
        .hasMessageContaining(Users.ANA_ID.toString());
    assertThatThrownBy(() -> handler.enable(Users.ANA_ID).block())
        .isInstanceOf(UserNotFoundException.class);
  }
}
