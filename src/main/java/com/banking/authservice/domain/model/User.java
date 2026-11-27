package com.banking.authservice.domain.model;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Someone who can log in to the platform: a username, the hash of a password and the roles the
 * access tokens of the user carry.
 *
 * <p>The username is kept in lower case, so upper and lower case name the same user. The password
 * itself is never kept. Instances are immutable; enabling and disabling return a new one. Instants
 * are kept to the microsecond, the precision of the database, so a user reads back equal to the one
 * that was stored.
 *
 * <p>Wrong passwords in a row are counted. When the count reaches the limit the user is locked for
 * a while: until {@code lockedUntil} it cannot log in, not even with its password. A correct login,
 * the end of the lock, an unlock and enabling the user start the count again.
 *
 * @param id identifier of the user
 * @param username name the user logs in with, in lower case
 * @param passwordHash hash of the password, as the password hasher wrote it
 * @param roles roles of the user; at least one, never {@link Role#SERVICE}
 * @param status whether the user can log in
 * @param failedAttempts wrong passwords in a row since the count last started
 * @param lockedUntil until when logins are refused because of wrong passwords; null when the user
 *     has not been locked
 * @param createdAt when the user was created
 * @param updatedAt when the user was last enabled or disabled
 */
public record User(
    UUID id,
    String username,
    String passwordHash,
    Set<Role> roles,
    UserStatus status,
    int failedAttempts,
    Instant lockedUntil,
    Instant createdAt,
    Instant updatedAt) {

  private static final Pattern VALID_USERNAME = Pattern.compile("[a-z0-9][a-z0-9._-]{2,49}");

  /** Checks the invariants of a user. */
  public User {
    Objects.requireNonNull(id, "id");
    Objects.requireNonNull(passwordHash, "passwordHash");
    Objects.requireNonNull(status, "status");
    Objects.requireNonNull(createdAt, "createdAt");
    Objects.requireNonNull(updatedAt, "updatedAt");
    if (username == null || !VALID_USERNAME.matcher(username).matches()) {
      throw new IllegalArgumentException(
          "username must have 3 to 50 lower case letters, digits, dots, underscores or hyphens");
    }
    if (failedAttempts < 0) {
      throw new IllegalArgumentException("failedAttempts cannot be negative");
    }
    if (roles == null || roles.isEmpty()) {
      throw new IllegalArgumentException("a user needs at least one role");
    }
    if (!roles.stream().allMatch(Role::assignableToUsers)) {
      throw new IllegalArgumentException("a user cannot have a role reserved for services");
    }
    roles = Collections.unmodifiableSet(EnumSet.copyOf(roles));
    lockedUntil = lockedUntil == null ? null : lockedUntil.truncatedTo(ChronoUnit.MICROS);
    createdAt = createdAt.truncatedTo(ChronoUnit.MICROS);
    updatedAt = updatedAt.truncatedTo(ChronoUnit.MICROS);
  }

  /**
   * A new user, able to log in at once.
   *
   * @param id identifier of the user
   * @param username name as it was typed; it is stored in lower case
   * @param passwordHash hash of the password
   * @param roles roles of the user
   * @param now the current instant
   * @return the user, {@link UserStatus#ACTIVE}
   */
  public static User register(
      UUID id, String username, String passwordHash, Set<Role> roles, Instant now) {
    return new User(
        id, normalize(username), passwordHash, roles, UserStatus.ACTIVE, 0, null, now, now);
  }

  /**
   * The form a username is stored and looked up in.
   *
   * @param username name as it was typed
   * @return the name in lower case, or null when there is none
   */
  public static String normalize(String username) {
    return username == null ? null : username.toLowerCase(Locale.ROOT);
  }

  public boolean isActive() {
    return status == UserStatus.ACTIVE;
  }

  public boolean isAdministrator() {
    return roles.contains(Role.ADMIN);
  }

  /**
   * Whether logins are refused because of too many wrong passwords.
   *
   * @param now the current instant
   * @return true until the lock ends
   */
  public boolean isLockedAt(Instant now) {
    return lockedUntil != null && now.isBefore(lockedUntil);
  }

  /** Whether wrong passwords are counted against the user or it has been locked. */
  public boolean hasLoginFailures() {
    return failedAttempts > 0 || lockedUntil != null;
  }

  /**
   * The same user with another status.
   *
   * @param newStatus status to change to
   * @param now the current instant
   * @return this user when it already has the status; otherwise the changed one
   */
  public User withStatus(UserStatus newStatus, Instant now) {
    if (status == newStatus) {
      return this;
    }
    return new User(
        id, username, passwordHash, roles, newStatus, failedAttempts, lockedUntil, createdAt, now);
  }

  /**
   * The same user after one more wrong password. A lock that already ended is forgotten first, so
   * the count starts again at one.
   *
   * @param maxFailedAttempts wrong passwords in a row that lock the user
   * @param lockDuration how long the lock lasts
   * @param now the current instant
   * @return the user with one more failed attempt, locked when the count reached the limit
   */
  public User withFailedLogin(int maxFailedAttempts, Duration lockDuration, Instant now) {
    int counted = lockedUntil == null ? failedAttempts : 0;
    int attempts = counted + 1;
    Instant lock = attempts >= maxFailedAttempts ? now.plus(lockDuration) : null;
    return new User(
        id, username, passwordHash, roles, status, attempts, lock, createdAt, updatedAt);
  }

  /**
   * The same user with no failed attempts and no lock.
   *
   * @return this user when it has neither; otherwise the cleared one
   */
  public User withoutLoginFailures() {
    if (!hasLoginFailures()) {
      return this;
    }
    return new User(id, username, passwordHash, roles, status, 0, null, createdAt, updatedAt);
  }

  /** Leaves the password hash out, so a user can be logged. */
  @Override
  public String toString() {
    return "User[id="
        + id
        + ", username="
        + username
        + ", roles="
        + roles
        + ", status="
        + status
        + "]";
  }
}
