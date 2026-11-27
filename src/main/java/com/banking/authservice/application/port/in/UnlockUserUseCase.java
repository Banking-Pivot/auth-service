package com.banking.authservice.application.port.in;

import com.banking.authservice.domain.model.User;
import java.util.UUID;
import reactor.core.publisher.Mono;

/** Ends the lock a user got for too many wrong passwords. */
public interface UnlockUserUseCase {

  /**
   * Forgets the failed attempts and the lock of the user. A user that has neither is left as it is.
   * The status does not change: a disabled user stays disabled.
   *
   * @param userId identifier of the user
   * @return the user, with no failed attempts and no lock, or {@code UserNotFoundException}
   */
  Mono<User> execute(UUID userId);
}
