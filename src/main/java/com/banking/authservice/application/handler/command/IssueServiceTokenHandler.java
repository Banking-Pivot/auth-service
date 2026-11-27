package com.banking.authservice.application.handler.command;

import com.banking.authservice.application.command.IssueServiceTokenCommand;
import com.banking.authservice.application.exception.InvalidClientException;
import com.banking.authservice.application.port.in.IssueServiceTokenUseCase;
import com.banking.authservice.application.port.out.ServiceClientsPort;
import com.banking.authservice.application.port.out.TokenSignerPort;
import com.banking.authservice.domain.model.AccessToken;
import com.banking.authservice.domain.model.Role;
import java.util.Set;
import reactor.core.publisher.Mono;

/** Issues the token a registered service calls other services with. */
public class IssueServiceTokenHandler implements IssueServiceTokenUseCase {

  private final ServiceClientsPort clients;
  private final TokenSignerPort signer;

  public IssueServiceTokenHandler(ServiceClientsPort clients, TokenSignerPort signer) {
    this.clients = clients;
    this.signer = signer;
  }

  @Override
  public Mono<AccessToken> execute(IssueServiceTokenCommand command) {
    return Mono.fromSupplier(
            () -> clients.authenticates(command.clientId(), command.clientSecret()))
        .flatMap(
            authenticated ->
                Boolean.TRUE.equals(authenticated)
                    ? signer.sign(command.clientId(), Set.of(Role.SERVICE))
                    : Mono.error(new InvalidClientException()));
  }
}
