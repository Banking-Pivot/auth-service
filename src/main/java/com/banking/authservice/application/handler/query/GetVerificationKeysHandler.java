package com.banking.authservice.application.handler.query;

import com.banking.authservice.application.port.in.GetVerificationKeysUseCase;
import com.banking.authservice.application.port.out.TokenSignerPort;
import com.banking.authservice.domain.model.vo.VerificationKey;
import java.util.List;
import reactor.core.publisher.Mono;

/** Tells which public keys verify the access tokens. */
public class GetVerificationKeysHandler implements GetVerificationKeysUseCase {

  private final TokenSignerPort signer;

  public GetVerificationKeysHandler(TokenSignerPort signer) {
    this.signer = signer;
  }

  @Override
  public Mono<List<VerificationKey>> execute() {
    return signer.verificationKeys();
  }
}
