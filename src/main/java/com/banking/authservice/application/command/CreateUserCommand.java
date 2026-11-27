package com.banking.authservice.application.command;

import com.banking.authservice.domain.model.Role;
import java.util.Set;

/**
 * A new user to create.
 *
 * @param username name of the user, as typed
 * @param password password of the user
 * @param roles roles the user gets
 */
public record CreateUserCommand(String username, String password, Set<Role> roles) {

  /** Leaves the password out. */
  @Override
  public String toString() {
    return "CreateUserCommand[username=" + username + ", roles=" + roles + "]";
  }
}
