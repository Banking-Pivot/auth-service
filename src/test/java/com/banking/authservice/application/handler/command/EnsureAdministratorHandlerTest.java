package com.banking.authservice.application.handler.command;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.banking.authservice.application.command.CreateUserCommand;
import com.banking.authservice.application.exception.UsernameAlreadyExistsException;
import com.banking.authservice.application.port.in.CreateUserUseCase;
import com.banking.authservice.application.port.out.UserStorePort;
import com.banking.authservice.domain.model.Role;
import com.banking.authservice.support.Users;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

@ExtendWith(MockitoExtension.class)
class EnsureAdministratorHandlerTest {

  @Mock private UserStorePort users;
  @Mock private CreateUserUseCase createUser;

  private EnsureAdministratorHandler handler;

  @BeforeEach
  void setUp() {
    handler = new EnsureAdministratorHandler(users, createUser, "admin", "first-password");
  }

  @Test
  void theFirstAdministratorIsCreatedWhenNoUserHasItsName() {
    when(users.findByUsername("admin")).thenReturn(Mono.empty());
    when(createUser.execute(any())).thenReturn(Mono.just(Users.admin()));

    assertThat(handler.execute().block()).isTrue();
    verify(createUser)
        .execute(new CreateUserCommand("admin", "first-password", Set.of(Role.ADMIN)));
  }

  @Test
  void anExistingUserWithThatNameIsLeftAsItIs() {
    when(users.findByUsername("admin")).thenReturn(Mono.just(Users.admin()));

    assertThat(handler.execute().block()).isFalse();
    verify(createUser, never()).execute(any());
  }

  @Test
  void anotherInstanceCreatingItAtTheSameTimeIsNotAFailure() {
    when(users.findByUsername("admin")).thenReturn(Mono.empty());
    when(createUser.execute(any()))
        .thenReturn(Mono.error(new UsernameAlreadyExistsException(new RuntimeException())));

    assertThat(handler.execute().block()).isFalse();
  }
}
