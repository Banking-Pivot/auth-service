package com.banking.authservice.application.command;

import com.banking.authservice.domain.model.enums.Role;
import java.util.Set;
import java.util.UUID;

/**
 * The new roles of a user and, optionally, its new password.
 *
 * @param userId identifier of the user
 * @param roles roles the user has from now on
 * @param password new password of the user; null when it keeps the one it has
 */
public record UpdateUserCommand(UUID userId, Set<Role> roles, String password) {

  /** Leaves the password out. */
  @Override
  public String toString() {
    return "UpdateUserCommand[userId=" + userId + ", roles=" + roles + "]";
  }
}
