package com.banking.authservice.application.handler.command;

import com.banking.authservice.application.exception.UserNotFoundException;
import com.banking.authservice.application.port.in.UnlockUserUseCase;
import com.banking.authservice.application.port.out.UserStorePort;
import com.banking.authservice.domain.model.User;
import java.util.UUID;
import reactor.core.publisher.Mono;

/** Unlocks users. Unlocking a user with no failed attempts and no lock stores nothing. */
public class UnlockUserHandler implements UnlockUserUseCase {

  private final UserStorePort users;

  public UnlockUserHandler(UserStorePort users) {
    this.users = users;
  }

  @Override
  public Mono<User> execute(UUID userId) {
    return users
        .findById(userId)
        .switchIfEmpty(Mono.error(new UserNotFoundException(userId)))
        .flatMap(this::unlock);
  }

  private Mono<User> unlock(User user) {
    User unlocked = user.withoutLoginFailures();
    return unlocked == user
        ? Mono.just(user)
        : users.clearLoginFailures(user.id()).thenReturn(unlocked);
  }
}
