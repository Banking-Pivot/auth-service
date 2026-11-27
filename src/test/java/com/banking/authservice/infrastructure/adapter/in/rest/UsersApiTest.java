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
