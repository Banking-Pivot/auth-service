package com.banking.authservice.infrastructure.startup;

import com.banking.authservice.application.port.in.EnsureAdministratorUseCase;
import com.banking.authservice.application.port.in.GetVerificationKeysUseCase;
import com.banking.authservice.domain.model.VerificationKey;
import java.time.Duration;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * What the service needs before it can answer its first request: the signing key (read from the
 * database, or created on the very first start) and the first administrator. A failure here stops
 * the startup, so a service that cannot sign tokens never looks healthy.
 */
@Slf4j
@Component
public class AuthStartup implements ApplicationRunner {

  private static final Duration TIMEOUT = Duration.ofSeconds(60);

  private final GetVerificationKeysUseCase verificationKeys;
  private final EnsureAdministratorUseCase ensureAdministrator;

  public AuthStartup(
      GetVerificationKeysUseCase verificationKeys, EnsureAdministratorUseCase ensureAdministrator) {
    this.verificationKeys = verificationKeys;
    this.ensureAdministrator = ensureAdministrator;
  }

  /**
   * Loads the signing key and creates the first administrator when it is missing.
   *
   * @param args not used
   */
  @Override
  public void run(ApplicationArguments args) {
    List<VerificationKey> keys = verificationKeys.execute().block(TIMEOUT);
    log.info(
        "Signing key ready. keyIds={}",
        keys == null ? List.of() : keys.stream().map(VerificationKey::keyId).toList());
    if (Boolean.TRUE.equals(ensureAdministrator.execute().block(TIMEOUT))) {
      log.info("First administrator created.");
    }
  }
}
