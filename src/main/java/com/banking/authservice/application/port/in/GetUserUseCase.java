package com.banking.authservice.application.port.in;

import com.banking.authservice.domain.model.User;
import java.util.UUID;
import reactor.core.publisher.Mono;

/** Reads one user. */
public interface GetUserUseCase {

  /**
   * Finds the user.
   *
   * @param userId identifier of the user
   * @return the user, or {@code UserNotFoundException}
   */
  Mono<User> execute(UUID userId);
}
