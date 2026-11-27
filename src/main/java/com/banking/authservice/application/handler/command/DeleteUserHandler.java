package com.banking.authservice.application.handler.command;

import com.banking.authservice.application.exception.InitialAdministratorProtectedException;
import com.banking.authservice.application.exception.UserNotFoundException;
import com.banking.authservice.application.port.in.DeleteUserUseCase;
import com.banking.authservice.application.port.out.UserStorePort;
import com.banking.authservice.domain.exception.AuthRuleViolationException;
import com.banking.authservice.domain.exception.RuleViolation;
import com.banking.authservice.domain.model.User;
import java.util.UUID;
import reactor.core.publisher.Mono;

/**
 * Removes users. The initial administrator cannot be deleted, and neither can the last
 * administrator that can log in: nobody could administer users after it.
 */
public class DeleteUserHandler implements DeleteUserUseCase {

  private final UserStorePort users;
  private final String initialAdministrator;

  /** Creates the handler with the name of the initial administrator, in lower case. */
  public DeleteUserHandler(UserStorePort users, String initialAdministrator) {
    this.users = users;
    this.initialAdministrator = initialAdministrator;
  }

  @Override
  public Mono<Void> execute(UUID userId) {
    return users
        .findById(userId)
        .switchIfEmpty(Mono.error(new UserNotFoundException(userId)))
        .flatMap(user -> keepsItsAdministrators(user).thenReturn(user))
        .flatMap(user -> users.delete(user.id()));
  }

  private Mono<Void> keepsItsAdministrators(User user) {
    if (user.username().equals(initialAdministrator)) {
      return Mono.error(
          new InitialAdministratorProtectedException(
              "The initial administrator cannot be deleted."));
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
                            "The last enabled administrator cannot be deleted.")));
  }
}
