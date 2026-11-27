package com.banking.authservice.application.handler.command;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.banking.authservice.application.command.CreateUserCommand;
import com.banking.authservice.application.exception.UsernameAlreadyExistsException;
import com.banking.authservice.application.port.out.PasswordHasherPort;
import com.banking.authservice.application.port.out.UserStorePort;
import com.banking.authservice.domain.model.User;
import com.banking.authservice.domain.model.enums.Role;
import com.banking.authservice.domain.model.enums.UserStatus;
import com.banking.authservice.support.Users;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

@ExtendWith(MockitoExtension.class)
class CreateUserHandlerTest {

  @Mock private UserStorePort users;
  @Mock private PasswordHasherPort hasher;

  private CreateUserHandler handler;

  @BeforeEach
  void setUp() {
    handler = new CreateUserHandler(users, hasher, Users.CLOCK, () -> Users.ANA_ID);
  }

  @Test
  void theUserIsStoredWithTheHashOfItsPasswordNeverThePassword() {
    when(hasher.hash("a-secret-password")).thenReturn(Mono.just("the-hash"));
    when(users.insert(any())).thenReturn(Mono.empty());
    CreateUserCommand command =
        new CreateUserCommand("Ana.Perez", "a-secret-password", Set.of(Role.USER));

    User created = handler.execute(command).block();

    ArgumentCaptor<User> stored = ArgumentCaptor.forClass(User.class);
    verify(users).insert(stored.capture());
    assertThat(stored.getValue()).isEqualTo(created);
    assertThat(created.id()).isEqualTo(Users.ANA_ID);
    assertThat(created.username()).isEqualTo("ana.perez");
    assertThat(created.passwordHash()).isEqualTo("the-hash");
    assertThat(created.roles()).containsExactly(Role.USER);
    assertThat(created.status()).isEqualTo(UserStatus.ACTIVE);
    assertThat(created.createdAt()).isEqualTo(Users.NOW);
    assertThat(command.toString()).contains("Ana.Perez").doesNotContain("a-secret-password");
  }

  @Test
  void aUsernameAlreadyTakenIsReported() {
    when(hasher.hash("a-secret-password")).thenReturn(Mono.just("the-hash"));
    when(users.insert(any()))
        .thenReturn(Mono.error(new UsernameAlreadyExistsException(new RuntimeException())));

    assertThatThrownBy(
            () ->
                handler
                    .execute(new CreateUserCommand("ana", "a-secret-password", Set.of(Role.USER)))
                    .block())
        .isInstanceOf(UsernameAlreadyExistsException.class)
        .hasMessage("Another user already has that username.");
  }

  @Test
  void aUserWithTheRoleOfServicesIsNotStored() {
    when(hasher.hash("a-secret-password")).thenReturn(Mono.just("the-hash"));

    assertThatThrownBy(
            () ->
                handler
                    .execute(
                        new CreateUserCommand("ana", "a-secret-password", Set.of(Role.SERVICE)))
                    .block())
        .isInstanceOf(IllegalArgumentException.class);
    verify(users, never()).insert(any());
  }
}
