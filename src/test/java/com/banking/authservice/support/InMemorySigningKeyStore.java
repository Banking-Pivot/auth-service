package com.banking.authservice.support;

import com.banking.authservice.infrastructure.adapter.out.security.SigningKeyStore;
import com.banking.authservice.infrastructure.adapter.out.security.StoredSigningKey;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import reactor.core.publisher.Mono;

/** A signing key store in memory that can also fail and lose a race, for unit tests. */
public final class InMemorySigningKeyStore implements SigningKeyStore {

  private final AtomicReference<StoredSigningKey> stored = new AtomicReference<>();
  private final AtomicReference<StoredSigningKey> winner = new AtomicReference<>();
  private final AtomicInteger inserts = new AtomicInteger();
  private final AtomicInteger finds = new AtomicInteger();
  private volatile boolean failNextFind;

  @Override
  public Mono<StoredSigningKey> find() {
    return Mono.defer(
        () -> {
          finds.incrementAndGet();
          if (failNextFind) {
            failNextFind = false;
            return Mono.error(new IllegalStateException("database unreachable"));
          }
          return Mono.justOrEmpty(stored.get());
        });
  }

  @Override
  public Mono<Boolean> insert(StoredSigningKey key) {
    return Mono.fromSupplier(
        () -> {
          StoredSigningKey first = winner.getAndSet(null);
          if (first != null) {
            stored.set(first);
            return false;
          }
          if (!stored.compareAndSet(null, key)) {
            return false;
          }
          inserts.incrementAndGet();
          return true;
        });
  }

  @Override
  public Mono<Void> delete(String keyId) {
    return Mono.fromRunnable(
        () -> stored.updateAndGet(key -> key != null && key.keyId().equals(keyId) ? null : key));
  }

  /** The next insert finds that another instance stored this key first. */
  public void loseTheRaceTo(StoredSigningKey other) {
    winner.set(other);
  }

  public void failNextFind() {
    failNextFind = true;
  }

  public StoredSigningKey current() {
    return stored.get();
  }

  public int inserts() {
    return inserts.get();
  }

  public int finds() {
    return finds.get();
  }
}
