package com.banking.authservice.application.handler.command;

import com.banking.authservice.application.exception.UserNotFoundException;
import com.banking.authservice.application.port.in.ChangeUserStatusUseCase;
import com.banking.authservice.application.port.out.UserStorePort;
import com.banking.authservice.domain.exception.AuthRuleViolationException;
import com.banking.authservice.domain.exception.RuleViolation;
import com.banking.authservice.domain.model.User;
import com.banking.authservice.domain.model.enums.UserStatus;
import java.time.Clock;
import java.util.UUID;
import reactor.core.publisher.Mono;

/**
 * Enables and disables users. Asking for the status a user already has does not change it. The last
 * administrator that can log in cannot be disabled: nobody could create or enable users after it.
 * Enabling also forgets the failed attempts and the lock of the user.
 */
public class ChangeUserStatusHandler implements ChangeUserStatusUseCase {

  private final UserStorePort users;
  private final Clock clock;

  public ChangeUserStatusHandler(UserStorePort users, Clock clock) {
    this.users = users;
    this.clock = clock;
  }

  @Override
  public Mono<User> disable(UUID userId) {
    return find(userId)
        .flatMap(user -> keepsAnAdministrator(user).thenReturn(user))
        .flatMap(user -> change(user, UserStatus.DISABLED));
  }

  @Override
  public Mono<User> enable(UUID userId) {
    return find(userId).flatMap(user -> change(user, UserStatus.ACTIVE)).flatMap(this::unlock);
  }

  private Mono<User> find(UUID userId) {
    return users.findById(userId).switchIfEmpty(Mono.error(new UserNotFoundException(userId)));
  }

  private Mono<Void> keepsAnAdministrator(User user) {
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
                            "The last enabled administrator cannot be disabled.")));
  }

  private Mono<User> unlock(User user) {
    User unlocked = user.withoutLoginFailures();
    return unlocked == user
        ? Mono.just(user)
        : users.clearLoginFailures(user.id()).thenReturn(unlocked);
  }

  private Mono<User> change(User user, UserStatus status) {
    User changed = user.withStatus(status, clock.instant());
    return changed == user ? Mono.just(user) : users.updateStatus(changed).thenReturn(changed);
  }
}
