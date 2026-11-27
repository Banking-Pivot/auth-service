package com.banking.authservice.infrastructure.adapter.in.rest;

import static org.assertj.core.api.Assertions.assertThat;

import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.UserResponse;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.UserRole;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.UserStatus;
import com.banking.authservice.support.IntegrationTest;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

/** Administration of users, end to end against a real database. */
class UsersApiTest extends IntegrationTest {

  @Test
  void aNewUserIsCreatedEnabledAndThePasswordNeverComesBack() {
    String body =
        createUser(newUser("Ana.Perez", "USER"))
            .expectStatus()
            .isCreated()
            .expectHeader()
            .valueMatches("Location", "/api/v1/auth/users/[0-9a-f-]{36}")
            .expectBody(String.class)
            .returnResult()
            .getResponseBody();

    assertThat(body)
        .contains("\"username\":\"ana.perez\"", "\"roles\":[\"USER\"]", "\"status\":\"ACTIVE\"")
        .doesNotContain(PASSWORD, "password", "$2");
    assertThat(storedHash("ana.perez")).startsWith("$2").doesNotContain(PASSWORD);
    loggedIn("ana.perez", PASSWORD);
  }

  @Test
  void theLocationOfANewUserAnswersWithThatUser() {
    UserResponse ana = created("ana", "ADMIN", "USER");

    UserResponse found =
        webTestClient
            .get()
            .uri("/api/v1/auth/users/{userId}", ana.getId())
            .exchange()
            .expectStatus()
            .isOk()
            .expectBody(UserResponse.class)
            .returnResult()
            .getResponseBody();

    assertThat(found).isEqualTo(ana);
    assertThat(found.getRoles()).containsExactly(UserRole.ADMIN, UserRole.USER);
    assertThat(found.getCreatedAt()).isEqualTo(found.getUpdatedAt());
  }

  @Test
  void aUsernameAlreadyTakenIsAConflictWhateverItsCase() {
    created("ana", "USER");

    expectError(createUser(newUser("ANA", "ADMIN")), 409, "USERNAME_ALREADY_EXISTS")
        .jsonPath("$.message")
        .isEqualTo("Another user already has that username.")
        .jsonPath("$.path")
        .isEqualTo("/api/v1/auth/users");
    expectError(createUser(newUser(ADMIN, "USER")), 409, "USERNAME_ALREADY_EXISTS");
    assertThat(userCount()).isEqualTo(2);
  }

  @Test
  void aRequestThatBreaksTheContractCreatesNothing() {
    expectError(createUser(newUser("ana", "SERVICE")), 400, "INVALID_REQUEST");
    expectError(createUser(newUser("ana")), 400, "INVALID_REQUEST")
        .jsonPath("$.message")
        .isEqualTo("Invalid or missing fields: roles.");
    expectError(createUser(newUser("an", "USER")), 400, "INVALID_REQUEST");
    expectError(createUser(newUser("ana perez", "USER")), 400, "INVALID_REQUEST");

    Map<String, Object> shortPassword = newUser("ana", "USER");
    shortPassword.put("password", "short");
    expectError(createUser(shortPassword), 400, "INVALID_REQUEST")
        .jsonPath("$.message")
        .isEqualTo("Invalid or missing fields: password.");

    // 72 characters that are more than 72 bytes: the contract lets it through, BCrypt does not.
    Map<String, Object> tooManyBytes = newUser("ana", "USER");
    tooManyBytes.put("password", "ñ".repeat(72));
    expectError(createUser(tooManyBytes), 400, "INVALID_REQUEST");

    assertThat(userCount()).isEqualTo(1);
  }

  @Test
  void theListIsPagedAndSortedByUsername() {
    created("zoe", "USER");
    created("bruno", "USER");

    webTestClient
        .get()
        .uri("/api/v1/auth/users?page=0&size=2")
        .exchange()
        .expectStatus()
        .isOk()
        .expectBody()
        .jsonPath("$.items.length()")
        .isEqualTo(2)
        .jsonPath("$.items[0].username")
        .isEqualTo("admin")
        .jsonPath("$.items[0].roles[0]")
        .isEqualTo("ADMIN")
        .jsonPath("$.items[1].username")
        .isEqualTo("bruno")
        .jsonPath("$.items[0].password")
        .doesNotExist()
        .jsonPath("$.items[0].passwordHash")
        .doesNotExist()
        .jsonPath("$.page")
        .isEqualTo(0)
        .jsonPath("$.size")
        .isEqualTo(2)
        .jsonPath("$.totalElements")
        .isEqualTo(3)
        .jsonPath("$.totalPages")
        .isEqualTo(2);

    webTestClient
        .get()
        .uri("/api/v1/auth/users?page=1&size=2")
        .exchange()
        .expectStatus()
        .isOk()
        .expectBody()
        .jsonPath("$.items.length()")
        .isEqualTo(1)
        .jsonPath("$.items[0].username")
        .isEqualTo("zoe");

    webTestClient
        .get()
        .uri("/api/v1/auth/users")
        .exchange()
        .expectStatus()
        .isOk()
        .expectBody()
        .jsonPath("$.size")
        .isEqualTo(20)
        .jsonPath("$.items.length()")
        .isEqualTo(3);
  }

  @Test
  void aPageOrASizeOutOfRangeIsRejected() {
    for (String query : List.of("page=-1", "size=0", "size=101", "page=abc")) {
      expectError(
          webTestClient.get().uri("/api/v1/auth/users?" + query).exchange(),
          400,
          "INVALID_REQUEST");
    }
  }

  @Test
  void disablingAndEnablingAUserChangesItsStatusAndCanBeRepeated() {
    UserResponse ana = created("ana", "USER");

    UserResponse disabled = changed(ana.getId(), "disable");
    UserResponse disabledAgain = changed(ana.getId(), "disable");

    assertThat(disabled.getStatus()).isEqualTo(UserStatus.DISABLED);
    assertThat(disabled.getUpdatedAt()).isAfterOrEqualTo(ana.getUpdatedAt());
    assertThat(disabled.getCreatedAt()).isEqualTo(ana.getCreatedAt());
    assertThat(disabledAgain).isEqualTo(disabled);

    UserResponse enabled = changed(ana.getId(), "enable");

    assertThat(enabled.getStatus()).isEqualTo(UserStatus.ACTIVE);
    assertThat(changed(ana.getId(), "enable")).isEqualTo(enabled);
  }

  @Test
  void theLastEnabledAdministratorCannotBeDisabled() {
    UUID admin = userId(ADMIN);

    expectError(userAction(admin, "disable"), 422, "LAST_ACTIVE_ADMIN")
        .jsonPath("$.message")
        .isEqualTo("The last enabled administrator cannot be disabled.");
    loggedIn(ADMIN, ADMIN_PASSWORD);

    // With a second administrator the first one can be disabled, and then the second cannot.
    UserResponse second = created("second.admin", "ADMIN");
    assertThat(changed(admin, "disable").getStatus()).isEqualTo(UserStatus.DISABLED);
    expectError(userAction(second.getId(), "disable"), 422, "LAST_ACTIVE_ADMIN");
  }

  @Test
  void anUnknownUserIsNotFoundAndAnIdThatIsNotAUuidIsRejected() {
    UUID unknown = UUID.randomUUID();

    expectError(
            webTestClient.get().uri("/api/v1/auth/users/{userId}", unknown).exchange(),
            404,
            "USER_NOT_FOUND")
        .jsonPath("$.message")
        .isEqualTo("The user does not exist.")
        .jsonPath("$.path")
        .isEqualTo("/api/v1/auth/users/" + unknown);
    expectError(userAction(unknown, "disable"), 404, "USER_NOT_FOUND");
    expectError(userAction(unknown, "enable"), 404, "USER_NOT_FOUND");
    expectError(
        webTestClient.get().uri("/api/v1/auth/users/not-a-uuid").exchange(),
        400,
        "INVALID_REQUEST");
  }

  @Test
  void updatingAUserReplacesItsRolesAndKeepsItsPassword() {
    UserResponse ana = created("ana", "USER");

    UserResponse updated = updated(ana.getId(), Map.of("roles", List.of("USER", "ADMIN")));

    assertThat(updated.getRoles()).containsExactly(UserRole.ADMIN, UserRole.USER);
    assertThat(updated.getId()).isEqualTo(ana.getId());
    assertThat(updated.getUsername()).isEqualTo("ana");
    assertThat(updated.getStatus()).isEqualTo(UserStatus.ACTIVE);
    assertThat(updated.getCreatedAt()).isEqualTo(ana.getCreatedAt());
    assertThat(updated.getUpdatedAt()).isAfterOrEqualTo(ana.getUpdatedAt());
    assertThat(found(ana.getId())).isEqualTo(updated);
    assertThat(loggedIn("ana", PASSWORD).getRoles()).hasSize(2);

    // The same roles again change nothing, not even when the user was last updated.
    assertThat(updated(ana.getId(), Map.of("roles", List.of("ADMIN", "USER")))).isEqualTo(updated);
  }

  @Test
  void updatingAUserWithAPasswordReplacesItAndEndsItsLock() {
    UserResponse ana = created("ana", "USER");
    for (int attempt = 0; attempt < 3; attempt++) {
      expectError(login("ana", "not-the-password"), 401, "INVALID_CREDENTIALS");
    }
    expectError(login("ana", PASSWORD), 401, "INVALID_CREDENTIALS");
    assertThat(found(ana.getId()).getLockedUntil()).isNotNull();

    String body =
        update(ana.getId(), Map.of("roles", List.of("USER"), "password", "Otra-clave-2026"))
            .expectStatus()
            .isOk()
            .expectBody(String.class)
            .returnResult()
            .getResponseBody();

    assertThat(body)
        .contains("\"roles\":[\"USER\"]", "\"failedAttempts\":0")
        .doesNotContain("Otra-clave-2026", "password", "lockedUntil", "$2");
    assertThat(storedHash("ana")).startsWith("$2").doesNotContain("Otra-clave-2026");
    loggedIn("ana", "Otra-clave-2026");
    expectError(login("ana", PASSWORD), 401, "INVALID_CREDENTIALS");
  }

  @Test
  void anUpdateThatBreaksTheContractChangesNothing() {
    UserResponse ana = created("ana", "USER");

    expectError(update(ana.getId(), Map.of("roles", List.of())), 400, "INVALID_REQUEST")
        .jsonPath("$.message")
        .isEqualTo("Invalid or missing fields: roles.");
    expectError(update(ana.getId(), Map.of("password", PASSWORD)), 400, "INVALID_REQUEST");
    expectError(update(ana.getId(), Map.of("roles", List.of("SERVICE"))), 400, "INVALID_REQUEST");
    expectError(
            update(ana.getId(), Map.of("roles", List.of("ADMIN"), "password", "short")),
            400,
            "INVALID_REQUEST")
        .jsonPath("$.message")
        .isEqualTo("Invalid or missing fields: password.");
    expectError(
        update(ana.getId(), Map.of("roles", List.of("ADMIN"), "password", "ñ".repeat(72))),
        400,
        "INVALID_REQUEST");
    expectError(
        update(ana.getId(), Map.of("roles", List.of("ADMIN"), "username", "other")),
        400,
        "INVALID_REQUEST");
    expectError(update("not-a-uuid", Map.of("roles", List.of("USER"))), 400, "INVALID_REQUEST");

    assertThat(found(ana.getId())).isEqualTo(ana);
    loggedIn("ana", PASSWORD);
  }

  @Test
  void deletingAUserRemovesItAndFreesItsUsername() {
    UserResponse ana = created("ana", "USER");

    delete(ana.getId()).expectStatus().isNoContent().expectBody().isEmpty();

    assertThat(userCount()).isEqualTo(1);
    expectError(
        webTestClient.get().uri("/api/v1/auth/users/{userId}", ana.getId()).exchange(),
        404,
        "USER_NOT_FOUND");
    expectError(delete(ana.getId()), 404, "USER_NOT_FOUND");
    expectError(login("ana", PASSWORD), 401, "INVALID_CREDENTIALS");
    assertThat(created("ana", "USER").getId()).isNotEqualTo(ana.getId());
  }

  @Test
  void theInitialAdministratorCannotBeDeletedNorLoseTheRoleOfAdministrator() {
    UUID admin = userId(ADMIN);
    created("second.admin", "ADMIN");

    expectError(delete(admin), 409, "INITIAL_ADMIN_PROTECTED")
        .jsonPath("$.message")
        .isEqualTo("The initial administrator cannot be deleted.")
        .jsonPath("$.path")
        .isEqualTo("/api/v1/auth/users/" + admin);
    expectError(update(admin, Map.of("roles", List.of("USER"))), 409, "INITIAL_ADMIN_PROTECTED")
        .jsonPath("$.message")
        .isEqualTo("The initial administrator cannot lose the role ADMIN.");

    assertThat(found(admin).getRoles()).containsExactly(UserRole.ADMIN);
    loggedIn(ADMIN, ADMIN_PASSWORD);

    // It can still get another role next to ADMIN.
    assertThat(updated(admin, Map.of("roles", List.of("ADMIN", "USER"))).getRoles())
        .containsExactly(UserRole.ADMIN, UserRole.USER);
    updated(admin, Map.of("roles", List.of("ADMIN")));
  }

  @Test
  void theLastEnabledAdministratorCannotBeDeletedNorLoseTheRoleOfAdministrator() {
    UserResponse second = created("second.admin", "ADMIN");
    changed(userId(ADMIN), "disable");

    expectError(delete(second.getId()), 422, "LAST_ACTIVE_ADMIN")
        .jsonPath("$.message")
        .isEqualTo("The last enabled administrator cannot be deleted.");
    expectError(update(second.getId(), Map.of("roles", List.of("USER"))), 422, "LAST_ACTIVE_ADMIN")
        .jsonPath("$.message")
        .isEqualTo("The last enabled administrator cannot lose the role ADMIN.");

    // With the initial administrator enabled again, the second one can be deleted.
    changed(userId(ADMIN), "enable");
    delete(second.getId()).expectStatus().isNoContent();
    assertThat(userCount()).isEqualTo(1);
  }

  @Test
  void updatingOrDeletingAnUnknownUserIsNotFound() {
    UUID unknown = UUID.randomUUID();

    expectError(update(unknown, Map.of("roles", List.of("USER"))), 404, "USER_NOT_FOUND")
        .jsonPath("$.path")
        .isEqualTo("/api/v1/auth/users/" + unknown);
    expectError(delete(unknown), 404, "USER_NOT_FOUND");
    expectError(
        webTestClient.delete().uri("/api/v1/auth/users/not-a-uuid").exchange(),
        400,
        "INVALID_REQUEST");
  }

  private WebTestClient.ResponseSpec update(Object userId, Object body) {
    return webTestClient
        .put()
        .uri("/api/v1/auth/users/{userId}", userId)
        .contentType(MediaType.APPLICATION_JSON)
        .bodyValue(body)
        .exchange();
  }

  private UserResponse updated(UUID userId, Object body) {
    return update(userId, body)
        .expectStatus()
        .isOk()
        .expectBody(UserResponse.class)
        .returnResult()
        .getResponseBody();
  }

  private WebTestClient.ResponseSpec delete(UUID userId) {
    return webTestClient.delete().uri("/api/v1/auth/users/{userId}", userId).exchange();
  }

  private UserResponse found(UUID userId) {
    return webTestClient
        .get()
        .uri("/api/v1/auth/users/{userId}", userId)
        .exchange()
        .expectStatus()
        .isOk()
        .expectBody(UserResponse.class)
        .returnResult()
        .getResponseBody();
  }

  private UserResponse changed(UUID userId, String action) {
    return userAction(userId, action)
        .expectStatus()
        .isOk()
        .expectBody(UserResponse.class)
        .returnResult()
        .getResponseBody();
  }

  private UUID userId(String username) {
    return databaseClient
        .sql("SELECT id FROM users WHERE username = :username")
        .bind("username", username)
        .map(row -> row.get(0, UUID.class))
        .one()
        .block();
  }

  private String storedHash(String username) {
    return databaseClient
        .sql("SELECT password_hash FROM users WHERE username = :username")
        .bind("username", username)
        .map(row -> row.get(0, String.class))
        .one()
        .block();
  }

  private long userCount() {
    return databaseClient
        .sql("SELECT count(*) FROM users")
        .map(row -> row.get(0, Long.class))
        .one()
        .block();
  }
}
