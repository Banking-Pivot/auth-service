package com.banking.authservice.application.exception;

/** The service token was refused: unknown client or wrong secret. It does not say which. */
public class InvalidClientException extends RuntimeException {

  public InvalidClientException() {
    super("The client ID or the client secret is not correct.");
  }
}
