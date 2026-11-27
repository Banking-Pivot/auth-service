package com.banking.authservice.infrastructure.adapter.in.rest;

import com.banking.authservice.application.command.CreateUserCommand;
import com.banking.authservice.application.command.UpdateUserCommand;
import com.banking.authservice.application.port.in.ChangeUserStatusUseCase;
import com.banking.authservice.application.port.in.CreateUserUseCase;
import com.banking.authservice.application.port.in.DeleteUserUseCase;
import com.banking.authservice.application.port.in.GetUserUseCase;
import com.banking.authservice.application.port.in.ListUsersUseCase;
import com.banking.authservice.application.port.in.UnlockUserUseCase;
import com.banking.authservice.application.port.in.UpdateUserUseCase;
import com.banking.authservice.application.query.PageRequest;
import com.banking.authservice.domain.model.enums.Role;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.api.UsersApiDelegate;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.CreateUserRequest;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.UpdateUserRequest;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.UserPageResponse;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.UserResponse;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.UserRole;
import java.net.URI;
import java.util.Collection;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Administration of users. Through the API Gateway these endpoints are for ADMIN only; this service
 * does not check tokens itself.
 */
@Component
public class UsersApiDelegateImpl implements UsersApiDelegate {

  static final String USERS_PATH = "/api/v1/auth/users/";

  private final CreateUserUseCase createUser;
  private final GetUserUseCase getUser;
  private final ListUsersUseCase listUsers;
  private final ChangeUserStatusUseCase changeUserStatus;
  private final UnlockUserUseCase unlockUser;
  private final UpdateUserUseCase updateUser;
  private final DeleteUserUseCase deleteUser;
  private final AuthRestMapper mapper;

  /** Creates the delegate with the use cases and the mapper that builds the responses. */
  public UsersApiDelegateImpl(
      CreateUserUseCase createUser,
      GetUserUseCase getUser,
      ListUsersUseCase listUsers,
      ChangeUserStatusUseCase changeUserStatus,
      UnlockUserUseCase unlockUser,
      UpdateUserUseCase updateUser,
      DeleteUserUseCase deleteUser,
      AuthRestMapper mapper) {
    this.createUser = createUser;
    this.getUser = getUser;
    this.listUsers = listUsers;
    this.changeUserStatus = changeUserStatus;
    this.unlockUser = unlockUser;
    this.updateUser = updateUser;
    this.deleteUser = deleteUser;
    this.mapper = mapper;
  }

  @Override
  public Mono<ResponseEntity<UserResponse>> createUser(
      Mono<CreateUserRequest> request, ServerWebExchange exchange) {
    return request
        .map(
            body ->
                new CreateUserCommand(
                    body.getUsername(), body.getPassword(), roles(body.getRoles())))
        .flatMap(createUser::execute)
        .map(
            user ->
                ResponseEntity.created(URI.create(USERS_PATH + user.id()))
                    .body(mapper.toResponse(user)));
  }

  @Override
  public Mono<ResponseEntity<UserPageResponse>> listUsers(
      Integer page, Integer size, ServerWebExchange exchange) {
    return Mono.fromCallable(() -> PageRequest.of(page, size))
        .flatMap(listUsers::execute)
        .map(mapper::toPage)
        .map(ResponseEntity::ok);
  }

  @Override
  public Mono<ResponseEntity<UserResponse>> getUser(UUID userId, ServerWebExchange exchange) {
    return getUser.execute(userId).map(mapper::toResponse).map(ResponseEntity::ok);
  }

  @Override
  public Mono<ResponseEntity<UserResponse>> disableUser(UUID userId, ServerWebExchange exchange) {
    return changeUserStatus.disable(userId).map(mapper::toResponse).map(ResponseEntity::ok);
  }

  @Override
  public Mono<ResponseEntity<UserResponse>> enableUser(UUID userId, ServerWebExchange exchange) {
    return changeUserStatus.enable(userId).map(mapper::toResponse).map(ResponseEntity::ok);
  }

  @Override
  public Mono<ResponseEntity<UserResponse>> unlockUser(UUID userId, ServerWebExchange exchange) {
    return unlockUser.execute(userId).map(mapper::toResponse).map(ResponseEntity::ok);
  }

  @Override
  public Mono<ResponseEntity<UserResponse>> updateUser(
      UUID userId, Mono<UpdateUserRequest> request, ServerWebExchange exchange) {
    return request
        .map(body -> new UpdateUserCommand(userId, roles(body.getRoles()), body.getPassword()))
        .flatMap(updateUser::execute)
        .map(mapper::toResponse)
        .map(ResponseEntity::ok);
  }

  @Override
  public Mono<ResponseEntity<Void>> deleteUser(UUID userId, ServerWebExchange exchange) {
    return deleteUser
        .execute(userId)
        .then(Mono.fromSupplier(() -> ResponseEntity.noContent().<Void>build()));
  }

  private static Set<Role> roles(Collection<UserRole> roles) {
    return roles.stream().map(role -> Role.valueOf(role.getValue())).collect(Collectors.toSet());
  }
}
