package com.banking.authservice.application.port.out;

/** The services allowed to ask for a service token. */
public interface ServiceClientsPort {

  /**
   * Whether the client is registered and the secret is its secret.
   *
   * @param clientId name the service says it has
   * @param clientSecret secret the service presents
   * @return true only for a registered client with its own secret
   */
  boolean authenticates(String clientId, String clientSecret);
}
