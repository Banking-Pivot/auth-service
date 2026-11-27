package com.banking.authservice.application.command;

/**
 * A person asking for an access token.
 *
 * @param username name of the user, as typed
 * @param password password, as typed
 */
public record LoginCommand(String username, String password) {

  /** Leaves the password out. */
  @Override
  public String toString() {
    return "LoginCommand[username=" + username + "]";
  }
}
