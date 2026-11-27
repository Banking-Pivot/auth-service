package com.banking.authservice.infrastructure.adapter.out.postgres;

import com.banking.authservice.domain.model.Role;
import com.banking.authservice.domain.model.User;
import com.banking.authservice.domain.model.UserStatus;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

/**
 * Row of {@code users}. The status is stored by name; the roles, as their names in alphabetical
 * order separated by commas.
 */
@Table("users")
public record UserRow(
    @Id UUID id,
    String username,
    String passwordHash,
    String roles,
    UserStatus status,
    int failedAttempts,
    Instant lockedUntil,
    Instant createdAt,
    Instant updatedAt) {

  private static final String SEPARATOR = ",";

  static UserRow of(User user) {
    return new UserRow(
        user.id(),
        user.username(),
        user.passwordHash(),
        user.roles().stream().map(Enum::name).sorted().collect(Collectors.joining(SEPARATOR)),
        user.status(),
        user.failedAttempts(),
        user.lockedUntil(),
        user.createdAt(),
        user.updatedAt());
  }

  User toUser() {
    return new User(
        id,
        username,
        passwordHash,
        Arrays.stream(roles.split(SEPARATOR)).map(Role::valueOf).collect(Collectors.toSet()),
        status,
        failedAttempts,
        lockedUntil,
        createdAt,
        updatedAt);
  }

  /** Leaves the password hash out. */
  @Override
  public String toString() {
    return "UserRow[id=" + id + ", username=" + username + ", status=" + status + "]";
  }
}
