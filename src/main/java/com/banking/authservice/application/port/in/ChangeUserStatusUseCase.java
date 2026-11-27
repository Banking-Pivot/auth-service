package com.banking.authservice.application.port.in;

import com.banking.authservice.domain.model.User;
import java.util.UUID;
import reactor.core.publisher.Mono;

/** Enables and disables users. A disabled user cannot log in. */
public interface ChangeUserStatusUseCase {

  /**
   * Stops the user from logging in. Tokens already issued stay valid until they expire.
   *
   * @param userId identifier of the user
   * @return the user, disabled; {@code UserNotFoundException}; or {@code
   *     AuthRuleViolationException} when it is the last enabled administrator
   */
  Mono<User> disable(UUID userId);

  /**
   * Lets the user log in again. Its failed attempts and its lock, if any, are forgotten too.
   *
   * @param userId identifier of the user
   * @return the user, enabled, or {@code UserNotFoundException}
   */
  Mono<User> enable(UUID userId);
}
