package com.banking.authservice.domain.exception;

import java.util.Objects;

/** A request that breaks a business rule of Auth Service. */
public class AuthRuleViolationException extends RuntimeException {

  private final RuleViolation violation;

  public AuthRuleViolationException(RuleViolation violation, String message) {
    super(message);
    this.violation = Objects.requireNonNull(violation, "violation");
  }

  public RuleViolation violation() {
    return violation;
  }
}
