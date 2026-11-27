package com.banking.authservice.infrastructure.adapter.in.rest;

import com.banking.authservice.application.model.ResultPage;
import com.banking.authservice.domain.model.User;
import com.banking.authservice.domain.model.vo.AccessToken;
import com.banking.authservice.domain.model.vo.VerificationKey;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.JwkResponse;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.JwkSetResponse;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.Role;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.TokenResponse;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.UserPageResponse;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.UserResponse;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.UserRole;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.UserStatus;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import org.springframework.stereotype.Component;

/** Builds the responses of the contract. A password or its hash never goes into one. */
@Component
public class AuthRestMapper {

  /** The token response, with the roles in alphabetical order. */
  public TokenResponse toResponse(AccessToken token) {
    return new TokenResponse()
        .accessToken(token.value())
        .tokenType(TokenResponse.TokenTypeEnum.BEARER)
        .expiresIn(token.expiresInSeconds())
        .roles(token.roles().stream().map(Enum::name).sorted().map(Role::fromValue).toList());
  }

  /**
   * The user response, with the roles in alphabetical order and the instants in UTC. A user that
   * has not been locked has no {@code lockedUntil}.
   */
  public UserResponse toResponse(User user) {
    return new UserResponse()
        .id(user.id())
        .username(user.username())
        .roles(user.roles().stream().map(Enum::name).sorted().map(UserRole::fromValue).toList())
        .status(UserStatus.fromValue(user.status().name()))
        .failedAttempts(user.failedAttempts())
        .lockedUntil(user.lockedUntil() == null ? null : utc(user.lockedUntil()))
        .createdAt(utc(user.createdAt()))
        .updatedAt(utc(user.updatedAt()));
  }

  /** One page of users. */
  public UserPageResponse toPage(ResultPage<User> page) {
    return new UserPageResponse()
        .items(page.items().stream().map(this::toResponse).toList())
        .page(page.page())
        .size(page.size())
        .totalElements(page.totalElements())
        .totalPages(page.totalPages());
  }

  /** The JWK Set with the public keys. */
  public JwkSetResponse toJwkSet(List<VerificationKey> keys) {
    return new JwkSetResponse().keys(keys.stream().map(AuthRestMapper::toJwk).toList());
  }

  private static JwkResponse toJwk(VerificationKey key) {
    return new JwkResponse()
        .kty(VerificationKey.KEY_TYPE)
        .kid(key.keyId())
        .use(VerificationKey.USE)
        .alg(VerificationKey.ALGORITHM)
        .n(key.modulus())
        .e(key.exponent());
  }

  private static OffsetDateTime utc(Instant instant) {
    return instant.atOffset(ZoneOffset.UTC);
  }
}
