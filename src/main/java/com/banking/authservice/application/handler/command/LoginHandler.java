package com.banking.authservice.application.handler.command;

import com.banking.authservice.application.command.LoginCommand;
import com.banking.authservice.application.exception.InvalidCredentialsException;
import com.banking.authservice.application.port.in.LoginUseCase;
import com.banking.authservice.application.port.out.PasswordHasherPort;
import com.banking.authservice.application.port.out.TokenSignerPort;
import com.banking.authservice.application.port.out.UserStorePort;
import com.banking.authservice.domain.model.User;
import com.banking.authservice.domain.model.vo.AccessToken;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import reactor.core.publisher.Mono;

/**
 * Logs a user in.
 *
 * <p>An unknown user, a wrong password, a disabled user and a locked user fail the same way and
 * take about the same time: the password is always checked, against a hash nobody knows the
 * password of when there is no user, and before looking at the lock when there is one. The answer
 * therefore tells neither which usernames exist nor which users are locked.
 *
 * <p>Wrong passwords in a row are counted and, at the limit, lock the user for a while. While it is
 * locked nothing is counted, so wrong passwords cannot keep a user locked beyond the duration of
 * the lock. The count is stored only if the user is still as it was read; when another login of the
 * same user got there first, the user is read again and the result of the password check is applied
 * to what is stored now, so no failed attempt is lost and none is forgotten by a login that started
 * before the lock.
 */
public class LoginHandler implements LoginUseCase {

  private final UserStorePort users;
  private final PasswordHasherPort hasher;
  private final TokenSignerPort signer;
  private final Clock clock;
  private final int maxFailedAttempts;
  private final Duration lockDuration;
  private final Mono<String> decoyHash;

  /**
   * Creates the handler; the decoy hash is made on the first login and kept.
   *
   * @param users where users are kept
   * @param hasher checks passwords
   * @param signer issues the tokens
   * @param clock the current instant
   * @param maxFailedAttempts wrong passwords in a row that lock a user
   * @param lockDuration how long a lock lasts
   */
  public LoginHandler(
      UserStorePort users,
      PasswordHasherPort hasher,
      TokenSignerPort signer,
      Clock clock,
      int maxFailedAttempts,
      Duration lockDuration) {
    this.users = users;
    this.hasher = hasher;
    this.signer = signer;
    this.clock = clock;
    this.maxFailedAttempts = maxFailedAttempts;
    this.lockDuration = lockDuration;
    this.decoyHash = Mono.defer(() -> hasher.hash(UUID.randomUUID().toString())).cache();
  }

  @Override
  public Mono<AccessToken> execute(LoginCommand command) {
    return users
        .findByUsername(User.normalize(command.username()))
        .map(Optional::of)
        .defaultIfEmpty(Optional.empty())
        .flatMap(found -> authenticate(found, command.password()));
  }

  private Mono<AccessToken> authenticate(Optional<User> found, String password) {
    Mono<String> hash = found.map(User::passwordHash).map(Mono::just).orElse(decoyHash);
    return hash.flatMap(stored -> hasher.matches(password, stored))
        .flatMap(
            matches ->
                found
                    .map(user -> decide(user, Boolean.TRUE.equals(matches)))
                    .orElseGet(LoginHandler::refused));
  }

  private Mono<AccessToken> decide(User user, boolean matches) {
    Instant now = clock.instant();
    if (user.isLockedAt(now)) {
      return refused();
    }
    if (!matches) {
      User failed = user.withFailedLogin(maxFailedAttempts, lockDuration, now);
      return store(user, failed, matches, refused());
    }
    if (!user.isActive()) {
      return refused();
    }
    Mono<AccessToken> token = Mono.defer(() -> signer.sign(user.username(), user.roles()));
    User cleared = user.withoutLoginFailures();
    return cleared == user ? token : store(user, cleared, matches, token);
  }

  private Mono<AccessToken> store(
      User read, User changed, boolean matches, Mono<AccessToken> outcome) {
    return users
        .updateLoginFailures(read, changed)
        .flatMap(stored -> Boolean.TRUE.equals(stored) ? outcome : decideAgain(read, matches));
  }

  // Another login changed the user first. Each round one of the competing logins is stored, so
  // this ends: with a failed attempt counted, with the user locked, or with a token.
  private Mono<AccessToken> decideAgain(User stale, boolean matches) {
    return users
        .findById(stale.id())
        .flatMap(current -> decide(current, matches))
        .switchIfEmpty(refused());
  }

  private static Mono<AccessToken> refused() {
    return Mono.error(InvalidCredentialsException::new);
  }
}
