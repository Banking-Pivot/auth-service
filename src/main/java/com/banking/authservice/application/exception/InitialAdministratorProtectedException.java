package com.banking.authservice.application.exception;

/** The initial administrator can neither be deleted nor lose the role of administrator. */
public class InitialAdministratorProtectedException extends RuntimeException {

  public InitialAdministratorProtectedException(String message) {
    super(message);
  }
}
