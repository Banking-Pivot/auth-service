package com.banking.authservice.application.port.in;

import com.banking.authservice.application.command.IssueServiceTokenCommand;
import com.banking.authservice.domain.model.vo.AccessToken;
import reactor.core.publisher.Mono;

/** Gives an access token to a registered service that presents its secret. */
public interface IssueServiceTokenUseCase {

  /**
   * Checks the secret and issues the token.
   *
   * @param command the client ID and the secret
   * @return the token with the role SERVICE, or {@code InvalidClientException}
   */
  Mono<AccessToken> execute(IssueServiceTokenCommand command);
}
