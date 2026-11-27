package com.banking.authservice.domain.exception;

/** Business rules a well-formed request can break. The name is the stable API error code. */
public enum RuleViolation {
  /** Disabling the user would leave the platform without an administrator that can log in. */
  LAST_ACTIVE_ADMIN
}
