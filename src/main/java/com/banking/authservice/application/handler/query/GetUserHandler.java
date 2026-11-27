package com.banking.authservice.application.handler.query;

import com.banking.authservice.application.exception.UserNotFoundException;
import com.banking.authservice.application.port.in.GetUserUseCase;
import com.banking.authservice.application.port.out.UserStorePort;
import com.banking.authservice.domain.model.User;
import java.util.UUID;
import reactor.core.publisher.Mono;

/** Reads one user. */
public class GetUserHandler implements GetUserUseCase {

  private final UserStorePort users;

  public GetUserHandler(UserStorePort users) {
    this.users = users;
  }

  @Override
  public Mono<User> execute(UUID userId) {
    return users.findById(userId).switchIfEmpty(Mono.error(new UserNotFoundException(userId)));
  }
}
