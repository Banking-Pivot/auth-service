package com.banking.authservice.domain.model;

/** What the holder of an access token may do. The API Gateway decides per route. */
public enum Role {
  /** Administers users and the product catalog. */
  ADMIN,
  /** Uses the banking APIs. */
  USER,
  /** A service calling other services. Only service tokens carry it; no user can have it. */
  SERVICE;

  /** Whether a user can be given this role. */
  public boolean assignableToUsers() {
    return this != SERVICE;
  }
}
