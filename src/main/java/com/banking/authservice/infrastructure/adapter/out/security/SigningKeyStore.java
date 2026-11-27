package com.banking.authservice.infrastructure.adapter.out.security;

import reactor.core.publisher.Mono;

/** Where the signing key is kept between restarts. It holds one key at most. */
public interface SigningKeyStore {

  Mono<StoredSigningKey> find();

  /**
   * Stores the key when there is none.
   *
   * @param key the key
   * @return true when it was stored; false when another key was already there, which happens when
   *     two instances start for the first time at once
   */
  Mono<Boolean> insert(StoredSigningKey key);

  Mono<Void> delete(String keyId);
}
