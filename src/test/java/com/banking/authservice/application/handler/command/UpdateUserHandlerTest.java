package com.banking.authservice.application.handler.command;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.banking.authservice.application.command.UpdateUserCommand;
import com.banking.authservice.application.exception.InitialAdministratorProtectedException;
import com.banking.authservice.application.exception.UserNotFoundException;
import com.banking.authservice.application.port.out.PasswordHasherPort;
import com.banking.authservice.application.port.out.UserStorePort;
import com.banking.authservice.domain.exception.AuthRuleViolationException;
import com.banking.authservice.domain.exception.RuleViolation;
import com.banking.authservice.domain.model.User;
import com.banking.authservice.domain.model.enums.Role;
import com.banking.authservice.domain.model.enums.UserStatus;
import com.banking.authservice.support.Users;
import java.time.Duration;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

@ExtendWith(MockitoExtension.class)
class UpdateUserHandlerTest {

  private static final UUID SECOND_ADMIN_ID =
      UUID.fromString("1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d");

  @Mock private UserStorePort users;
  @Mock private PasswordHasherPort hasher;

  private UpdateUserHandler handler;

  @BeforeEach
  void setUp() {
    handler = new UpdateUserHandler(users, hasher, Users.CLOCK, "admin");
  }

  @Test
  void newRolesAreStoredWithWhenTheyChangedAndThePasswordIsKept() {
    when(users.findById(Users.ANA_ID)).thenReturn(Mono.just(Users.ana()));
    when(users.updateRoles(any())).thenReturn(Mono.empty());

    User updated = handler.execute(command(Users.ANA_ID, null, Role.ADMIN, Role.USER)).block();

    assertThat(updated.roles()).containsExactlyInAnyOrder(Role.ADMIN, Role.USER);
    assertThat(updated.passwordHash()).isEqualTo(Users.ana().passwordHash());
    assertThat(updated.updatedAt()).isEqualTo(Users.NOW);
    assertThat(updated.createdAt()).isEqualTo(Users.ana().createdAt());
    verify(users).updateRoles(updated);
    verify(users, never()).updateRolesAndPassword(any());
    verifyNoInteractions(hasher);
  }

  @Test
  void theRolesAUserAlreadyHasWithNoNewPasswordStoreNothing() {
    User ana = Users.ana();
    when(users.findById(Users.ANA_ID)).thenReturn(Mono.just(ana));

    assertThat(handler.execute(command(Users.ANA_ID, null, Role.USER)).block()).isSameAs(ana);
    verify(users, never()).updateRoles(any());
    verify(users, never()).updateRolesAndPassword(any());
  }

  @Test
  void aNewPasswordIsStoredAsItsHashAndForgetsTheFailedAttemptsAndTheLock() {
    User locked = Users.ana().withFailedLogin(1, Duration.ofMinutes(15), Users.NOW);
    when(users.findById(Users.ANA_ID)).thenReturn(Mono.just(locked));
    when(hasher.hash("a-new-password")).thenReturn(Mono.just("the-new-hash"));
    when(users.updateRolesAndPassword(any())).thenReturn(Mono.empty());
    UpdateUserCommand command = command(Users.ANA_ID, "a-new-password", Role.USER);

    User updated = handler.execute(command).block();

    assertThat(updated.passwordHash()).isEqualTo("the-new-hash");
    assertThat(updated.roles()).containsExactly(Role.USER);
    assertThat(updated.failedAttempts()).isZero();
    assertThat(updated.lockedUntil()).isNull();
    assertThat(updated.updatedAt()).isEqualTo(Users.NOW);
    verify(users).updateRolesAndPassword(updated);
    verify(users, never()).updateRoles(any());
    assertThat(command.toString())
        .contains(Users.ANA_ID.toString())
        .doesNotContain("a-new-password");
  }

  @Test
  void theInitialAdministratorCannotLoseTheRoleOfAdministrator() {
    when(users.findById(Users.ADMIN_ID)).thenReturn(Mono.just(Users.admin()));

    assertThatThrownBy(() -> handler.execute(command(Users.ADMIN_ID, null, Role.USER)).block())
        .isInstanceOf(InitialAdministratorProtectedException.class)
        .hasMessage("The initial administrator cannot lose the role ADMIN.");
    verify(users, never()).updateRoles(any());
    verify(users, never()).countActiveAdministrators();
  }

  @Test
  void theInitialAdministratorCanGetMoreRolesAndANewPassword() {
    when(users.findById(Users.ADMIN_ID)).thenReturn(Mono.just(Users.admin()));
    when(hasher.hash("a-new-password")).thenReturn(Mono.just("the-new-hash"));
    when(users.updateRolesAndPassword(any())).thenReturn(Mono.empty());

    User updated =
        handler.execute(command(Users.ADMIN_ID, "a-new-password", Role.ADMIN, Role.USER)).block();

    assertThat(updated.roles()).containsExactlyInAnyOrder(Role.ADMIN, Role.USER);
    assertThat(updated.passwordHash()).isEqualTo("the-new-hash");
  }

  @Test
  void theLastEnabledAdministratorCannotLoseTheRoleOfAdministrator() {
    when(users.findById(SECOND_ADMIN_ID)).thenReturn(Mono.just(secondAdmin()));
    when(users.countActiveAdministrators()).thenReturn(Mono.just(1L));

    assertThatThrownBy(() -> handler.execute(command(SECOND_ADMIN_ID, null, Role.USER)).block())
        .isInstanceOfSatisfying(
            AuthRuleViolationException.class,
            error -> assertThat(error.violation()).isEqualTo(RuleViolation.LAST_ACTIVE_ADMIN))
        .hasMessage("The last enabled administrator cannot lose the role ADMIN.");
    verify(users, never()).updateRoles(any());
  }

  @Test
  void anAdministratorCanLoseTheRoleWhileAnotherOneCanLogIn() {
    when(users.findById(SECOND_ADMIN_ID)).thenReturn(Mono.just(secondAdmin()));
    when(users.countActiveAdministrators()).thenReturn(Mono.just(2L));
    when(users.updateRoles(any())).thenReturn(Mono.empty());

    User updated = handler.execute(command(SECOND_ADMIN_ID, null, Role.USER)).block();

    assertThat(updated.isAdministrator()).isFalse();
  }

  @Test
  void aDisabledAdministratorCanLoseTheRoleWithoutCountingAdministrators() {
    User disabled = secondAdmin().withStatus(UserStatus.DISABLED, Users.NOW.minusSeconds(60));
    when(users.findById(SECOND_ADMIN_ID)).thenReturn(Mono.just(disabled));
    when(users.updateRoles(any())).thenReturn(Mono.empty());

    User updated = handler.execute(command(SECOND_ADMIN_ID, null, Role.USER)).block();

    assertThat(updated.isAdministrator()).isFalse();
    assertThat(updated.isActive()).isFalse();
    verify(users, never()).countActiveAdministrators();
  }

  @Test
  void aRoleReservedForServicesIsNotStored() {
    when(users.findById(Users.ANA_ID)).thenReturn(Mono.just(Users.ana()));

    assertThatThrownBy(() -> handler.execute(command(Users.ANA_ID, null, Role.SERVICE)).block())
        .isInstanceOf(IllegalArgumentException.class);
    verify(users, never()).updateRoles(any());
  }

  @Test
  void anUnknownUserIsNotFound() {
    when(users.findById(Users.ANA_ID)).thenReturn(Mono.empty());

    assertThatThrownBy(() -> handler.execute(command(Users.ANA_ID, null, Role.USER)).block())
        .isInstanceOf(UserNotFoundException.class)
        .hasMessageContaining(Users.ANA_ID.toString());
    verifyNoInteractions(hasher);
  }

  private static UpdateUserCommand command(UUID userId, String password, Role... roles) {
    return new UpdateUserCommand(userId, Set.of(roles), password);
  }

  private static User secondAdmin() {
    return User.register(
        SECOND_ADMIN_ID, "second.admin", "hash", Set.of(Role.ADMIN), Users.NOW.minusSeconds(60));
  }
}
