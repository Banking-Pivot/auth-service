package com.banking.authservice.infrastructure.adapter.in.rest;

import com.banking.authservice.application.command.IssueServiceTokenCommand;
import com.banking.authservice.application.command.LoginCommand;
import com.banking.authservice.application.port.in.GetVerificationKeysUseCase;
import com.banking.authservice.application.port.in.IssueServiceTokenUseCase;
import com.banking.authservice.application.port.in.LoginUseCase;
import com.banking.authservice.domain.model.AccessToken;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.api.AuthenticationApiDelegate;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.JwkSetResponse;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.LoginRequest;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.ServiceTokenRequest;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.TokenResponse;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Logins, service tokens and the JWK Set. A token is answered with {@code Cache-Control: no-store}
 * so no intermediary keeps it.
 */
@Component
public class AuthenticationApiDelegateImpl implements AuthenticationApiDelegate {

  private final LoginUseCase login;
  private final IssueServiceTokenUseCase issueServiceToken;
  private final GetVerificationKeysUseCase getVerificationKeys;
  private final AuthRestMapper mapper;

  /** Creates the delegate with the use cases and the mapper that builds the responses. */
  public AuthenticationApiDelegateImpl(
      LoginUseCase login,
      IssueServiceTokenUseCase issueServiceToken,
      GetVerificationKeysUseCase getVerificationKeys,
      AuthRestMapper mapper) {
    this.login = login;
    this.issueServiceToken = issueServiceToken;
    this.getVerificationKeys = getVerificationKeys;
    this.mapper = mapper;
  }

  @Override
  public Mono<ResponseEntity<TokenResponse>> login(
      Mono<LoginRequest> request, ServerWebExchange exchange) {
    return request
        .map(body -> new LoginCommand(body.getUsername(), body.getPassword()))
        .flatMap(login::execute)
        .map(this::token);
  }

  @Override
  public Mono<ResponseEntity<TokenResponse>> issueServiceToken(
      Mono<ServiceTokenRequest> request, ServerWebExchange exchange) {
    return request
        .map(body -> new IssueServiceTokenCommand(body.getClientId(), body.getClientSecret()))
        .flatMap(issueServiceToken::execute)
        .map(this::token);
  }

  @Override
  public Mono<ResponseEntity<JwkSetResponse>> getJwkSet(ServerWebExchange exchange) {
    return getVerificationKeys.execute().map(mapper::toJwkSet).map(ResponseEntity::ok);
  }

  private ResponseEntity<TokenResponse> token(AccessToken token) {
    return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(mapper.toResponse(token));
  }
}
