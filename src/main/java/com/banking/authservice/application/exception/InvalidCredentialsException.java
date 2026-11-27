package com.banking.authservice.application.exception;

/**
 * The login was refused: unknown user, wrong password, disabled user or locked user. It does not
 * say which, so the answer does not reveal which users exist nor which ones are locked.
 */
public class InvalidCredentialsException extends RuntimeException {

  public InvalidCredentialsException() {
    super("The username or the password is not correct.");
  }
}
