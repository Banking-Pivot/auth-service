package com.banking.authservice.infrastructure.adapter.in.rest;

import com.banking.authservice.application.exception.InitialAdministratorProtectedException;
import com.banking.authservice.application.exception.InvalidClientException;
import com.banking.authservice.application.exception.InvalidCredentialsException;
import com.banking.authservice.application.exception.UserNotFoundException;
import com.banking.authservice.application.exception.UsernameAlreadyExistsException;
import com.banking.authservice.domain.exception.AuthRuleViolationException;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.ErrorResponse;
import com.banking.authservice.infrastructure.correlation.CorrelationId;
import jakarta.validation.ConstraintViolationException;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.support.WebExchangeBindException;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.server.MissingRequestValueException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ServerWebInputException;
import org.springframework.web.server.UnsupportedMediaTypeStatusException;

/**
 * Maps every failure to the contract's ErrorResponse with a stable code.
 *
 * <p>Also receives errors raised before the delegate runs (415 from request mapping, 400 from
 * parameter validation), because WebFlux routes dispatch errors to {@code @ExceptionHandler}
 * methods. Messages name the invalid fields but never echo their values: a request can carry a
 * password or a client secret.
 */
@Slf4j
@RestControllerAdvice
public class AuthExceptionHandler {

  private final Clock clock;

  public AuthExceptionHandler(Clock clock) {
    this.clock = clock;
  }

  /**
   * Answers 401 {@code INVALID_CREDENTIALS} for an unknown user, a wrong password, a disabled user
   * or a locked user, all with the same message.
   */
  @ExceptionHandler(InvalidCredentialsException.class)
  public ResponseEntity<ErrorResponse> handleInvalidCredentials(
      InvalidCredentialsException exception, ServerWebExchange exchange) {
    // Neither the username nor the password goes to the log.
    log.warn("Login refused. corrId={}", CorrelationId.of(exchange));
    return error(HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", exception.getMessage(), exchange);
  }

  /** Answers 401 {@code INVALID_CLIENT} for an unknown client or a wrong secret. */
  @ExceptionHandler(InvalidClientException.class)
  public ResponseEntity<ErrorResponse> handleInvalidClient(
      InvalidClientException exception, ServerWebExchange exchange) {
    log.warn("Service token refused. corrId={}", CorrelationId.of(exchange));
    return error(HttpStatus.UNAUTHORIZED, "INVALID_CLIENT", exception.getMessage(), exchange);
  }

  /** Answers 404 {@code USER_NOT_FOUND}. */
  @ExceptionHandler(UserNotFoundException.class)
  public ResponseEntity<ErrorResponse> handleNotFound(
      UserNotFoundException exception, ServerWebExchange exchange) {
    return error(HttpStatus.NOT_FOUND, "USER_NOT_FOUND", "The user does not exist.", exchange);
  }

  /** Answers 409 {@code USERNAME_ALREADY_EXISTS}. */
  @ExceptionHandler(UsernameAlreadyExistsException.class)
  public ResponseEntity<ErrorResponse> handleUsernameTaken(
      UsernameAlreadyExistsException exception, ServerWebExchange exchange) {
    return error(HttpStatus.CONFLICT, "USERNAME_ALREADY_EXISTS", exception.getMessage(), exchange);
  }

  /**
   * Answers 409 {@code INITIAL_ADMIN_PROTECTED} when the initial administrator would be deleted or
   * would lose the role of administrator.
   */
  @ExceptionHandler(InitialAdministratorProtectedException.class)
  public ResponseEntity<ErrorResponse> handleInitialAdministratorProtected(
      InitialAdministratorProtectedException exception, ServerWebExchange exchange) {
    return error(HttpStatus.CONFLICT, "INITIAL_ADMIN_PROTECTED", exception.getMessage(), exchange);
  }

  /**
   * Answers 422 for a broken business rule, with the name of the rule as the code and the message
   * of the domain.
   */
  @ExceptionHandler(AuthRuleViolationException.class)
  public ResponseEntity<ErrorResponse> handleBusinessRule(
      AuthRuleViolationException exception, ServerWebExchange exchange) {
    return error(
        HttpStatus.UNPROCESSABLE_CONTENT,
        exception.violation().name(),
        exception.getMessage(),
        exchange);
  }

  /**
   * Answers 400 {@code INVALID_REQUEST} for a value the contract lets through and the domain or the
   * password hash refuses, such as a password longer than 72 bytes.
   */
  @ExceptionHandler(IllegalArgumentException.class)
  public ResponseEntity<ErrorResponse> handleInvalidValue(
      IllegalArgumentException exception, ServerWebExchange exchange) {
    return invalidRequest("The request contains invalid values.", exchange);
  }

  /** Answers 400 {@code INVALID_REQUEST} for a missing value. */
  @ExceptionHandler(MissingRequestValueException.class)
  public ResponseEntity<ErrorResponse> handleMissingValue(
      MissingRequestValueException exception, ServerWebExchange exchange) {
    return invalidRequest("The request is missing a required value.", exchange);
  }

  /**
   * Answers 400 {@code INVALID_REQUEST} for a body that fails validation, naming the fields but not
   * their values.
   */
  @ExceptionHandler(WebExchangeBindException.class)
  public ResponseEntity<ErrorResponse> handleInvalidBody(
      WebExchangeBindException exception, ServerWebExchange exchange) {
    String fields =
        exception.getFieldErrors().stream()
            .map(FieldError::getField)
            .distinct()
            .sorted()
            .collect(Collectors.joining(", "));
    return invalidRequest("Invalid or missing fields: " + fields + ".", exchange);
  }

  /** Answers 400 {@code INVALID_REQUEST} for a body or a parameter that cannot be read. */
  @ExceptionHandler(ServerWebInputException.class)
  public ResponseEntity<ErrorResponse> handleInvalidInput(
      ServerWebInputException exception, ServerWebExchange exchange) {
    return invalidRequest(
        "The request is malformed or contains invalid, unknown or missing fields.", exchange);
  }

  /** Answers 400 {@code INVALID_REQUEST} for a parameter that breaks a constraint. */
  @ExceptionHandler(ConstraintViolationException.class)
  public ResponseEntity<ErrorResponse> handleConstraintViolation(
      ConstraintViolationException exception, ServerWebExchange exchange) {
    return invalidRequest("The request contains invalid parameters.", exchange);
  }

  /**
   * Answers 400 {@code INVALID_REQUEST} for invalid request parameters. An invalid return value is
   * a fault of this service and answers 500 {@code INTERNAL_ERROR}.
   */
  @ExceptionHandler(HandlerMethodValidationException.class)
  public ResponseEntity<ErrorResponse> handleMethodValidation(
      HandlerMethodValidationException exception, ServerWebExchange exchange) {
    if (exception.isForReturnValue()) {
      return unexpected(exception, exchange);
    }
    return invalidRequest("The request contains invalid parameters.", exchange);
  }

  /** Answers 415 {@code UNSUPPORTED_MEDIA_TYPE} when the request body is not JSON. */
  @ExceptionHandler(UnsupportedMediaTypeStatusException.class)
  public ResponseEntity<ErrorResponse> handleUnsupportedMediaType(
      UnsupportedMediaTypeStatusException exception, ServerWebExchange exchange) {
    return error(
        HttpStatus.UNSUPPORTED_MEDIA_TYPE,
        "UNSUPPORTED_MEDIA_TYPE",
        "Request body must use application/json.",
        exchange);
  }

  /**
   * Keeps the 4xx status WebFlux raised, such as 404 for an unknown route, with the name of the
   * status as the code. A 5xx or unknown status answers 500 {@code INTERNAL_ERROR}.
   */
  @ExceptionHandler(ResponseStatusException.class)
  public ResponseEntity<ErrorResponse> handleHttpError(
      ResponseStatusException exception, ServerWebExchange exchange) {
    HttpStatus status = HttpStatus.resolve(exception.getStatusCode().value());
    if (status == null || status.is5xxServerError()) {
      return unexpected(exception, exchange);
    }
    return error(status, status.name(), status.getReasonPhrase() + ".", exchange);
  }

  /** Answers 500 {@code INTERNAL_ERROR} for anything else, without exposing why. */
  @ExceptionHandler(Exception.class)
  public ResponseEntity<ErrorResponse> handleUnexpected(
      Exception exception, ServerWebExchange exchange) {
    return unexpected(exception, exchange);
  }

  private ResponseEntity<ErrorResponse> unexpected(
      Exception exception, ServerWebExchange exchange) {
    // No payloads or SQL messages in the log; the type is enough to correlate with the request.
    log.error(
        "Unhandled auth request failure. corrId={}, exceptionType={}",
        CorrelationId.of(exchange),
        exception.getClass().getName());
    return error(
        HttpStatus.INTERNAL_SERVER_ERROR,
        "INTERNAL_ERROR",
        "The request could not be completed.",
        exchange);
  }

  private ResponseEntity<ErrorResponse> invalidRequest(String message, ServerWebExchange exchange) {
    return error(HttpStatus.BAD_REQUEST, "INVALID_REQUEST", message, exchange);
  }

  private ResponseEntity<ErrorResponse> error(
      HttpStatus status, String code, String message, ServerWebExchange exchange) {
    ErrorResponse response =
        new ErrorResponse()
            .code(code)
            .message(message)
            .timestamp(OffsetDateTime.now(clock).withOffsetSameInstant(ZoneOffset.UTC))
            .path(exchange.getRequest().getPath().value())
            .traceId(CorrelationId.of(exchange));
    return ResponseEntity.status(status).body(response);
  }
}
