package com.banking.authservice.infrastructure.adapter.out.security;

import com.banking.authservice.application.port.out.PasswordHasherPort;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Hashes passwords with BCrypt. Every hash has its own random salt, so two users with the same
 * password have different hashes.
 *
 * <p>BCrypt is slow on purpose (tens of milliseconds), so it runs on the scheduler for blocking
 * work and never on the threads that serve the requests.
 */
public class BcryptPasswordHasher implements PasswordHasherPort {

  private final BCryptPasswordEncoder encoder;

  public BcryptPasswordHasher(int strength) {
    this.encoder = new BCryptPasswordEncoder(strength);
  }

  @Override
  public Mono<String> hash(String password) {
    return Mono.fromCallable(() -> encoder.encode(password))
        .subscribeOn(Schedulers.boundedElastic());
  }

  @Override
  public Mono<Boolean> matches(String password, String hash) {
    return Mono.fromCallable(() -> encoder.matches(password, hash))
        .subscribeOn(Schedulers.boundedElastic());
  }
}
