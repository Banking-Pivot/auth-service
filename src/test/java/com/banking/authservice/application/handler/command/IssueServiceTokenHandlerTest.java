package com.banking.authservice.application.handler.command;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.banking.authservice.application.command.IssueServiceTokenCommand;
import com.banking.authservice.application.exception.InvalidClientException;
import com.banking.authservice.application.port.out.ServiceClientsPort;
import com.banking.authservice.application.port.out.TokenSignerPort;
import com.banking.authservice.domain.model.enums.Role;
import com.banking.authservice.domain.model.vo.AccessToken;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

@ExtendWith(MockitoExtension.class)
class IssueServiceTokenHandlerTest {

  @Mock private ServiceClientsPort clients;
  @Mock private TokenSignerPort signer;
  @InjectMocks private IssueServiceTokenHandler handler;

  @Test
  void aRegisteredServiceWithItsSecretGetsATokenWithTheRoleService() {
    AccessToken issued = new AccessToken("a.b.c", 3600, Set.of(Role.SERVICE));
    when(clients.authenticates("account-service", "its-secret")).thenReturn(true);
    when(signer.sign("account-service", Set.of(Role.SERVICE))).thenReturn(Mono.just(issued));

    AccessToken token =
        handler.execute(new IssueServiceTokenCommand("account-service", "its-secret")).block();

    assertThat(token).isSameAs(issued);
  }

  @Test
  void aWrongSecretOrAnUnknownClientIsRefusedAndNothingIsSigned() {
    IssueServiceTokenCommand command = new IssueServiceTokenCommand("account-service", "guess");
    when(clients.authenticates("account-service", "guess")).thenReturn(false);

    assertThatThrownBy(() -> handler.execute(command).block())
        .isInstanceOf(InvalidClientException.class)
        .hasMessage("The client ID or the client secret is not correct.");
    verify(signer, never()).sign(any(), any());
    assertThat(command.toString()).contains("account-service").doesNotContain("guess");
  }
}
