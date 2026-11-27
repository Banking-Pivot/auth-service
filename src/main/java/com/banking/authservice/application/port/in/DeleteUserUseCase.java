package com.banking.authservice.application.port.in;

import java.util.UUID;
import reactor.core.publisher.Mono;

/** Removes users. */
public interface DeleteUserUseCase {

  /**
   * Removes the user for good. Tokens already issued stay valid until they expire.
   *
   * @param userId identifier of the user
   * @return completion; {@code UserNotFoundException}; {@code
   *     InitialAdministratorProtectedException} when it is the initial administrator; or {@code
   *     AuthRuleViolationException} when it is the last enabled administrator
   */
  Mono<Void> execute(UUID userId);
}
