package com.banking.authservice.infrastructure.config;

import com.banking.authservice.application.handler.command.ChangeUserStatusHandler;
import com.banking.authservice.application.handler.command.CreateUserHandler;
import com.banking.authservice.application.handler.command.EnsureAdministratorHandler;
import com.banking.authservice.application.handler.command.IssueServiceTokenHandler;
import com.banking.authservice.application.handler.command.LoginHandler;
import com.banking.authservice.application.handler.command.UnlockUserHandler;
import com.banking.authservice.application.handler.query.GetUserHandler;
import com.banking.authservice.application.handler.query.GetVerificationKeysHandler;
import com.banking.authservice.application.handler.query.ListUsersHandler;
import com.banking.authservice.application.port.in.ChangeUserStatusUseCase;
import com.banking.authservice.application.port.in.CreateUserUseCase;
import com.banking.authservice.application.port.in.EnsureAdministratorUseCase;
import com.banking.authservice.application.port.in.GetUserUseCase;
import com.banking.authservice.application.port.in.GetVerificationKeysUseCase;
import com.banking.authservice.application.port.in.IssueServiceTokenUseCase;
import com.banking.authservice.application.port.in.ListUsersUseCase;
import com.banking.authservice.application.port.in.LoginUseCase;
import com.banking.authservice.application.port.in.UnlockUserUseCase;
import com.banking.authservice.application.port.out.PasswordHasherPort;
import com.banking.authservice.application.port.out.ServiceClientsPort;
import com.banking.authservice.application.port.out.TokenSignerPort;
import com.banking.authservice.application.port.out.UserStorePort;
import com.banking.authservice.infrastructure.adapter.out.security.BcryptPasswordHasher;
import com.banking.authservice.infrastructure.adapter.out.security.ConfiguredServiceClients;
import com.banking.authservice.infrastructure.adapter.out.security.PrivateKeyCipher;
import com.banking.authservice.infrastructure.adapter.out.security.RsaTokenSigner;
import com.banking.authservice.infrastructure.adapter.out.security.SigningKeyStore;
import java.time.Clock;
import java.util.UUID;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Builds the use cases and the security adapters that need settings. The application and domain
 * layers have no Spring annotations; this class is where they meet their adapters.
 */
@Configuration
@EnableConfigurationProperties(AuthProperties.class)
public class AuthBeanConfiguration {

  @Bean
  public Clock authClock() {
    return Clock.systemUTC();
  }

  @Bean
  public PasswordHasherPort passwordHasher(AuthProperties properties) {
    return new BcryptPasswordHasher(properties.passwords().bcryptStrength());
  }

  @Bean
  public ServiceClientsPort serviceClients(AuthProperties properties) {
    return new ConfiguredServiceClients(properties.serviceClients());
  }

  /** The signer of the access tokens, with the issuer, the lifetime and the secret of the key. */
  @Bean
  public TokenSignerPort tokenSigner(
      SigningKeyStore signingKeys, AuthProperties properties, Clock clock) {
    return new RsaTokenSigner(
        signingKeys,
        new PrivateKeyCipher(properties.jwt().keyEncryptionSecret()),
        properties.jwt().issuer(),
        properties.jwt().accessTokenTtl(),
        clock,
        UUID::randomUUID);
  }

  /** The login, with the wrong passwords that lock a user and how long the lock lasts. */
  @Bean
  public LoginUseCase loginUseCase(
      UserStorePort users,
      PasswordHasherPort hasher,
      TokenSignerPort signer,
      Clock clock,
      AuthProperties properties) {
    return new LoginHandler(
        users,
        hasher,
        signer,
        clock,
        properties.login().maxFailedAttempts(),
        properties.login().lockDuration());
  }

  @Bean
  public IssueServiceTokenUseCase issueServiceTokenUseCase(
      ServiceClientsPort clients, TokenSignerPort signer) {
    return new IssueServiceTokenHandler(clients, signer);
  }

  @Bean
  public GetVerificationKeysUseCase getVerificationKeysUseCase(TokenSignerPort signer) {
    return new GetVerificationKeysHandler(signer);
  }

  @Bean
  public CreateUserUseCase createUserUseCase(
      UserStorePort users, PasswordHasherPort hasher, Clock clock) {
    return new CreateUserHandler(users, hasher, clock, UUID::randomUUID);
  }

  @Bean
  public GetUserUseCase getUserUseCase(UserStorePort users) {
    return new GetUserHandler(users);
  }

  @Bean
  public ListUsersUseCase listUsersUseCase(UserStorePort users) {
    return new ListUsersHandler(users);
  }

  @Bean
  public ChangeUserStatusUseCase changeUserStatusUseCase(UserStorePort users, Clock clock) {
    return new ChangeUserStatusHandler(users, clock);
  }

  @Bean
  public UnlockUserUseCase unlockUserUseCase(UserStorePort users) {
    return new UnlockUserHandler(users);
  }

  /** The creation of the first administrator, with the name and the password of the settings. */
  @Bean
  public EnsureAdministratorUseCase ensureAdministratorUseCase(
      UserStorePort users, CreateUserUseCase createUser, AuthProperties properties) {
    return new EnsureAdministratorHandler(
        users,
        createUser,
        properties.bootstrap().adminUsername(),
        properties.bootstrap().adminPassword());
  }
}
