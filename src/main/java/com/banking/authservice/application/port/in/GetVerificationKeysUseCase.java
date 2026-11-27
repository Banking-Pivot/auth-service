package com.banking.authservice.application.port.in;

import com.banking.authservice.domain.model.VerificationKey;
import java.util.List;
import reactor.core.publisher.Mono;

/** Tells which public keys verify the access tokens. */
public interface GetVerificationKeysUseCase {

  Mono<List<VerificationKey>> execute();
}
