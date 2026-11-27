package com.banking.authservice.application.handler.command;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.banking.authservice.application.exception.InitialAdministratorProtectedException;
import com.banking.authservice.application.exception.UserNotFoundException;
import com.banking.authservice.application.port.out.UserStorePort;
import com.banking.authservice.domain.exception.AuthRuleViolationException;
import com.banking.authservice.domain.exception.RuleViolation;
import com.banking.authservice.domain.model.User;
import com.banking.authservice.domain.model.enums.Role;
import com.banking.authservice.domain.model.enums.UserStatus;
import com.banking.authservice.support.Users;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

@ExtendWith(MockitoExtension.class)
class DeleteUserHandlerTest {

  private static final UUID SECOND_ADMIN_ID =
      UUID.fromString("1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d");

  @Mock private UserStorePort users;

  private DeleteUserHandler handler;

  @BeforeEach
  void setUp() {
    handler = new DeleteUserHandler(users, "admin");
  }

  @Test
  void aUserIsRemovedFromTheStore() {
    when(users.findById(Users.ANA_ID)).thenReturn(Mono.just(Users.ana()));
    when(users.delete(Users.ANA_ID)).thenReturn(Mono.empty());

    handler.execute(Users.ANA_ID).block();

    verify(users).delete(Users.ANA_ID);
    // Not an administrator: nobody counts administrators.
    verify(users, never()).countActiveAdministrators();
  }

  @Test
  void theInitialAdministratorCannotBeDeletedEvenWhenAnotherOneCanLogIn() {
    when(users.findById(Users.ADMIN_ID)).thenReturn(Mono.just(Users.admin()));

    assertThatThrownBy(() -> handler.execute(Users.ADMIN_ID).block())
        .isInstanceOf(InitialAdministratorProtectedException.class)
        .hasMessage("The initial administrator cannot be deleted.");
    verify(users, never()).delete(any());
    verify(users, never()).countActiveAdministrators();
  }

  @Test
  void theLastEnabledAdministratorCannotBeDeleted() {
    when(users.findById(SECOND_ADMIN_ID)).thenReturn(Mono.just(secondAdmin()));
    when(users.countActiveAdministrators()).thenReturn(Mono.just(1L));

    assertThatThrownBy(() -> handler.execute(SECOND_ADMIN_ID).block())
        .isInstanceOfSatisfying(
            AuthRuleViolationException.class,
            error -> assertThat(error.violation()).isEqualTo(RuleViolation.LAST_ACTIVE_ADMIN))
        .hasMessage("The last enabled administrator cannot be deleted.");
    verify(users, never()).delete(any());
  }

  @Test
  void anAdministratorCanBeDeletedWhileAnotherOneCanLogIn() {
    when(users.findById(SECOND_ADMIN_ID)).thenReturn(Mono.just(secondAdmin()));
    when(users.countActiveAdministrators()).thenReturn(Mono.just(2L));
    when(users.delete(SECOND_ADMIN_ID)).thenReturn(Mono.empty());

    handler.execute(SECOND_ADMIN_ID).block();

    verify(users).delete(SECOND_ADMIN_ID);
  }

  @Test
  void aDisabledAdministratorIsDeletedWithoutCountingAdministrators() {
    User disabled = secondAdmin().withStatus(UserStatus.DISABLED, Users.NOW.minusSeconds(60));
    when(users.findById(SECOND_ADMIN_ID)).thenReturn(Mono.just(disabled));
    when(users.delete(SECOND_ADMIN_ID)).thenReturn(Mono.empty());

    handler.execute(SECOND_ADMIN_ID).block();

    verify(users).delete(SECOND_ADMIN_ID);
    verify(users, never()).countActiveAdministrators();
  }

  @Test
  void anUnknownUserIsNotFound() {
    when(users.findById(Users.ANA_ID)).thenReturn(Mono.empty());

    assertThatThrownBy(() -> handler.execute(Users.ANA_ID).block())
        .isInstanceOf(UserNotFoundException.class)
        .hasMessageContaining(Users.ANA_ID.toString());
    verify(users, never()).delete(any());
  }

  private static User secondAdmin() {
    return User.register(
        SECOND_ADMIN_ID, "second.admin", "hash", Set.of(Role.ADMIN), Users.NOW.minusSeconds(60));
  }
}
