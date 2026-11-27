package com.banking.authservice.domain.model;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

/**
 * A signed access token, ready to be sent as {@code Authorization: Bearer}.
 *
 * @param value the token itself (a JWT)
 * @param expiresInSeconds seconds from its issue until it expires
 * @param roles roles the token carries
 */
public record AccessToken(String value, long expiresInSeconds, Set<Role> roles) {

  /** Rejects a token without a value and copies the roles. */
  public AccessToken {
    Objects.requireNonNull(value, "value");
    roles = Collections.unmodifiableSet(EnumSet.copyOf(roles));
  }

  /** Leaves the token out, so the result of a login can be logged. */
  @Override
  public String toString() {
    return "AccessToken[expiresInSeconds=" + expiresInSeconds + ", roles=" + roles + "]";
  }
}
