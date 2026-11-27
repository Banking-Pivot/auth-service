package com.banking.authservice.application.exception;

import java.util.UUID;

/** No user has the identifier. */
public class UserNotFoundException extends RuntimeException {

  public UserNotFoundException(UUID userId) {
    super("User " + userId + " does not exist.");
  }
}
