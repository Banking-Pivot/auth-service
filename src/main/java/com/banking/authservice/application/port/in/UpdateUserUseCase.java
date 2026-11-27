package com.banking.authservice.application.port.in;

import com.banking.authservice.application.command.UpdateUserCommand;
import com.banking.authservice.domain.model.User;
import reactor.core.publisher.Mono;

/** Replaces the roles of a user and, when asked, its password. */
public interface UpdateUserUseCase {

  /**
   * Updates the user. A new password also forgets its failed attempts and its lock. The username
   * and the status do not change.
   *
   * @param command the user, its new roles and, optionally, its new password
   * @return the user, updated; {@code UserNotFoundException}; {@code
   *     InitialAdministratorProtectedException} when the initial administrator would lose the role
   *     of administrator; or {@code AuthRuleViolationException} when the last enabled administrator
   *     would lose it
   */
  Mono<User> execute(UpdateUserCommand command);
}
