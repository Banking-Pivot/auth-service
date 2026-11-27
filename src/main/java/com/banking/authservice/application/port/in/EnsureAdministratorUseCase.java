package com.banking.authservice.application.port.in;

import reactor.core.publisher.Mono;

/** Makes sure the platform has its first administrator, the one that creates the other users. */
public interface EnsureAdministratorUseCase {

  /**
   * Creates the first administrator when no user has its username.
   *
   * @return true when the user was created; false when it already existed
   */
  Mono<Boolean> execute();
}
