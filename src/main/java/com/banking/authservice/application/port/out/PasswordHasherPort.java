package com.banking.authservice.application.port.out;

import reactor.core.publisher.Mono;

/** Turns passwords into hashes that cannot be turned back, and checks a password against one. */
public interface PasswordHasherPort {

  Mono<String> hash(String password);

  /**
   * Whether the password is the one the hash was made from.
   *
   * @param password password as typed
   * @param hash hash written by {@link #hash(String)}
   * @return true when they match
   */
  Mono<Boolean> matches(String password, String hash);
}
