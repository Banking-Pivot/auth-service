package com.banking.authservice.domain.exception;

/** Business rules a well-formed request can break. The name is the stable API error code. */
public enum RuleViolation {
  /**
   * Disabling or deleting the user, or taking the role of administrator from it, would leave the
   * platform without an administrator that can log in.
   */
  LAST_ACTIVE_ADMIN
}
