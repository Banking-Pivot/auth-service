package com.banking.authservice.application.handler.command;

import com.banking.authservice.application.command.CreateUserCommand;
import com.banking.authservice.application.port.in.CreateUserUseCase;
import com.banking.authservice.application.port.out.PasswordHasherPort;
import com.banking.authservice.application.port.out.UserStorePort;
import com.banking.authservice.domain.model.User;
import java.time.Clock;
import java.util.UUID;
import java.util.function.Supplier;
import reactor.core.publisher.Mono;

/** Creates users. Only the hash of the password reaches the store. */
public class CreateUserHandler implements CreateUserUseCase {

  private final UserStorePort users;
  private final PasswordHasherPort hasher;
  private final Clock clock;
  private final Supplier<UUID> identifiers;

  /** Creates the handler with the source of the identifiers of new users. */
  public CreateUserHandler(
      UserStorePort users, PasswordHasherPort hasher, Clock clock, Supplier<UUID> identifiers) {
    this.users = users;
    this.hasher = hasher;
    this.clock = clock;
    this.identifiers = identifiers;
  }

  @Override
  public Mono<User> execute(CreateUserCommand command) {
    return hasher
        .hash(command.password())
        .map(
            hash ->
                User.register(
                    identifiers.get(), command.username(), hash, command.roles(), clock.instant()))
        .flatMap(user -> users.insert(user).thenReturn(user));
  }
}
