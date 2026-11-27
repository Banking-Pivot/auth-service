package com.banking.authservice.application.handler.command;

import com.banking.authservice.application.command.CreateUserCommand;
import com.banking.authservice.application.exception.UsernameAlreadyExistsException;
import com.banking.authservice.application.port.in.CreateUserUseCase;
import com.banking.authservice.application.port.in.EnsureAdministratorUseCase;
import com.banking.authservice.application.port.out.UserStorePort;
import com.banking.authservice.domain.model.Role;
import com.banking.authservice.domain.model.User;
import java.util.Set;
import reactor.core.publisher.Mono;

/**
 * Creates the first administrator when it is missing. An existing user with that name is left as it
 * is, with whatever password, roles and status it has.
 */
public class EnsureAdministratorHandler implements EnsureAdministratorUseCase {

  private final UserStorePort users;
  private final CreateUserUseCase createUser;
  private final String username;
  private final String password;

  /** Creates the handler with the name and the password the first administrator gets. */
  public EnsureAdministratorHandler(
      UserStorePort users, CreateUserUseCase createUser, String username, String password) {
    this.users = users;
    this.createUser = createUser;
    this.username = username;
    this.password = password;
  }

  @Override
  public Mono<Boolean> execute() {
    return users
        .findByUsername(User.normalize(username))
        .map(existing -> false)
        .switchIfEmpty(Mono.defer(this::create));
  }

  // Another instance starting at the same time may create it first: that is the same outcome.
  private Mono<Boolean> create() {
    return createUser
        .execute(new CreateUserCommand(username, password, Set.of(Role.ADMIN)))
        .map(created -> true)
        .onErrorReturn(UsernameAlreadyExistsException.class, false);
  }
}
