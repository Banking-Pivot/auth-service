package com.banking.authservice.application.port.out;

import com.banking.authservice.application.model.ResultPage;
import com.banking.authservice.application.query.PageRequest;
import com.banking.authservice.domain.model.User;
import java.util.UUID;
import reactor.core.publisher.Mono;

/** Where users are kept. */
public interface UserStorePort {

  /**
   * Stores a new user.
   *
   * @param user the user
   * @return completion, or {@code UsernameAlreadyExistsException} when the username is taken
   */
  Mono<Void> insert(User user);

  Mono<User> findById(UUID userId);

  /**
   * Finds a user by its name.
   *
   * @param username name in lower case
   * @return the user, or empty
   */
  Mono<User> findByUsername(String username);

  /**
   * Stores the status of a user and when it changed.
   *
   * @param changed the user with its new status
   * @return completion
   */
  Mono<Void> updateStatus(User changed);

  /**
   * Stores the failed attempts and the lock of a user, only if both are still the ones that were
   * read. Two logins of the same user at the same time therefore cannot overwrite each other: the
   * one that comes second is told and has to read the user again.
   *
   * @param expected the user as it was read
   * @param changed the same user with its new failed attempts and lock
   * @return true when it was stored; false when the user changed in the meantime
   */
  Mono<Boolean> updateLoginFailures(User expected, User changed);

  /**
   * Forgets the failed attempts and the lock of a user, whatever they are.
   *
   * @param userId identifier of the user
   * @return completion
   */
  Mono<Void> clearLoginFailures(UUID userId);

  /** How many administrators can log in. */
  Mono<Long> countActiveAdministrators();

  Mono<ResultPage<User>> findPage(PageRequest pageRequest);
}
