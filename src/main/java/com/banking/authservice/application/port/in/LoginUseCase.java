package com.banking.authservice.application.port.in;

import com.banking.authservice.application.command.LoginCommand;
import com.banking.authservice.domain.model.AccessToken;
import reactor.core.publisher.Mono;

/** Gives an access token to a user that proves who it is with its password. */
public interface LoginUseCase {

  /**
   * Checks the password and issues the token. Wrong passwords in a row are counted and lock the
   * user for a while; a locked user is refused like a wrong password.
   *
   * @param command the username and the password
   * @return the token with the roles of the user, or {@code InvalidCredentialsException}
   */
  Mono<AccessToken> execute(LoginCommand command);
}
