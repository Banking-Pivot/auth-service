package com.banking.authservice.application.handler.command;

import com.banking.authservice.application.command.UpdateUserCommand;
import com.banking.authservice.application.exception.InitialAdministratorProtectedException;
import com.banking.authservice.application.exception.UserNotFoundException;
import com.banking.authservice.application.port.in.UpdateUserUseCase;
import com.banking.authservice.application.port.out.PasswordHasherPort;
import com.banking.authservice.application.port.out.UserStorePort;
import com.banking.authservice.domain.exception.AuthRuleViolationException;
import com.banking.authservice.domain.exception.RuleViolation;
import com.banking.authservice.domain.model.User;
import com.banking.authservice.domain.model.enums.Role;
import java.time.Clock;
import java.time.Instant;
import reactor.core.publisher.Mono;

/**
 * Replaces the roles of a user and, when the command carries one, its password. Only the hash of
 * the password reaches the store. The initial administrator keeps the role of administrator, and so
 * does the last administrator that can log in: nobody could administer users after it. Asking for
 * the roles a user already has, with no new password, stores nothing.
 */
public class UpdateUserHandler implements UpdateUserUseCase {

  private final UserStorePort users;
  private final PasswordHasherPort hasher;
  private final Clock clock;
  private final String initialAdministrator;

  /** Creates the handler with the name of the initial administrator, in lower case. */
  public UpdateUserHandler(
      UserStorePort users, PasswordHasherPort hasher, Clock clock, String initialAdministrator) {
    this.users = users;
    this.hasher = hasher;
    this.clock = clock;
    this.initialAdministrator = initialAdministrator;
  }

  @Override
  public Mono<User> execute(UpdateUserCommand command) {
    return users
        .findById(command.userId())
        .switchIfEmpty(Mono.error(new UserNotFoundException(command.userId())))
        .flatMap(user -> keepsItsAdministrators(user, command).thenReturn(user))
        .flatMap(user -> update(user, command));
  }

  private Mono<Void> keepsItsAdministrators(User user, UpdateUserCommand command) {
    if (command.roles().contains(Role.ADMIN)) {
      return Mono.empty();
    }
    if (user.username().equals(initialAdministrator)) {
      return Mono.error(
          new InitialAdministratorProtectedException(
              "The initial administrator cannot lose the role ADMIN."));
    }
    if (!user.isActive() || !user.isAdministrator()) {
      return Mono.empty();
    }
    return users
        .countActiveAdministrators()
        .flatMap(
            administrators ->
                administrators > 1
                    ? Mono.<Void>empty()
                    : Mono.error(
                        new AuthRuleViolationException(
                            RuleViolation.LAST_ACTIVE_ADMIN,
                            "The last enabled administrator cannot lose the role ADMIN.")));
  }

  private Mono<User> update(User user, UpdateUserCommand command) {
    Instant now = clock.instant();
    User withRoles = user.withRoles(command.roles(), now);
    if (command.password() == null) {
      return withRoles == user
          ? Mono.just(user)
          : users.updateRoles(withRoles).thenReturn(withRoles);
    }
    return hasher
        .hash(command.password())
        .map(hash -> withRoles.withPasswordHash(hash, now))
        .flatMap(changed -> users.updateRolesAndPassword(changed).thenReturn(changed));
  }
}
