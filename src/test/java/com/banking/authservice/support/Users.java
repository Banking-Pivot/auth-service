package com.banking.authservice.support;

import com.banking.authservice.domain.model.User;
import com.banking.authservice.domain.model.enums.Role;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.UUID;

/** Users and a fixed clock for unit tests. */
public final class Users {

  public static final Instant NOW = Instant.parse("2026-11-20T15:00:00Z");
  public static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
  public static final UUID ANA_ID = UUID.fromString("3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b");
  public static final UUID ADMIN_ID = UUID.fromString("8d7c6b5a-4f3e-4d2c-8b1a-0f9e8d7c6b5a");

  private Users() {}

  /** An enabled user named ana with the role USER. */
  public static User ana() {
    return User.register(ANA_ID, "ana", "hash-of-ana", Set.of(Role.USER), NOW.minusSeconds(3600));
  }

  /** An enabled administrator named admin. */
  public static User admin() {
    return User.register(
        ADMIN_ID, "admin", "hash-of-admin", Set.of(Role.ADMIN), NOW.minusSeconds(7200));
  }
}
