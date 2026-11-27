package com.banking.authservice.application.port.out;

import com.banking.authservice.domain.model.AccessToken;
import com.banking.authservice.domain.model.Role;
import com.banking.authservice.domain.model.VerificationKey;
import java.util.List;
import java.util.Set;
import reactor.core.publisher.Mono;

/** Signs access tokens and publishes the keys that verify them. */
public interface TokenSignerPort {

  /**
   * Issues a token.
   *
   * @param subject who the token is for: a username or a client ID
   * @param roles roles the token carries
   * @return the signed token
   */
  Mono<AccessToken> sign(String subject, Set<Role> roles);

  Mono<List<VerificationKey>> verificationKeys();
}
