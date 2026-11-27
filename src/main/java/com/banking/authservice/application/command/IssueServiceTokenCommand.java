package com.banking.authservice.application.command;

/**
 * A service asking for an access token.
 *
 * @param clientId name the service is registered under
 * @param clientSecret secret the service presents
 */
public record IssueServiceTokenCommand(String clientId, String clientSecret) {

  /** Leaves the secret out. */
  @Override
  public String toString() {
    return "IssueServiceTokenCommand[clientId=" + clientId + "]";
  }
}
