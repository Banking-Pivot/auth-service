package com.banking.authservice.application.exception;

/** Another user already has the username. */
public class UsernameAlreadyExistsException extends RuntimeException {

  public UsernameAlreadyExistsException(Throwable cause) {
    super("Another user already has that username.", cause);
  }
}
