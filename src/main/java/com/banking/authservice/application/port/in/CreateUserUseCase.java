package com.banking.authservice.application.port.in;

import com.banking.authservice.application.command.CreateUserCommand;
import com.banking.authservice.domain.model.User;
import reactor.core.publisher.Mono;

/** Creates a user. */
public interface CreateUserUseCase {

  /**
   * Stores the user with the hash of its password.
   *
   * @param command the username, the password and the roles
   * @return the user, or {@code UsernameAlreadyExistsException}
   */
  Mono<User> execute(CreateUserCommand command);
}
