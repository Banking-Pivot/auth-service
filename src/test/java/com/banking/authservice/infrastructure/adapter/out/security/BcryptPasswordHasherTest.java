package com.banking.authservice.infrastructure.adapter.out.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class BcryptPasswordHasherTest {

  // The lowest cost BCrypt accepts keeps the test fast.
  private final BcryptPasswordHasher hasher = new BcryptPasswordHasher(4);

  @Test
  void aPasswordMatchesItsHashAndNoOtherPasswordDoes() {
    String hash = hasher.hash("a-secret-password").block();

    assertThat(hash).startsWith("$2").doesNotContain("a-secret-password");
    assertThat(hasher.matches("a-secret-password", hash).block()).isTrue();
    assertThat(hasher.matches("A-secret-password", hash).block()).isFalse();
  }

  @Test
  void theSamePasswordGivesADifferentHashEveryTime() {
    assertThat(hasher.hash("a-secret-password").block())
        .isNotEqualTo(hasher.hash("a-secret-password").block());
  }

  @Test
  void hashingRunsOffTheCallingThread() {
    String caller = Thread.currentThread().getName();

    String worker =
        hasher.hash("a-secret-password").map(hash -> Thread.currentThread().getName()).block();

    assertThat(worker).isNotEqualTo(caller).startsWith("boundedElastic");
  }
}
