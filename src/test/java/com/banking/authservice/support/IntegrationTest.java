package com.banking.authservice.support;

import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.TokenResponse;
import com.banking.authservice.infrastructure.adapter.in.rest.generated.model.UserResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Boots the whole service on a random port against a real PostgreSQL in Docker.
 *
 * <p>The application keeps its real {@code spring.config.import}. A stub Config Server serves the
 * settings of {@code stub-config/auth-service.yml} and the location of the database; a real Vault
 * holds what the Config Server never serves: the database user and password, the password of the
 * first administrator, the secret the signing key is encrypted with and the secrets of the service
 * clients. All of them start once, before any Spring context.
 *
 * <p>Every test starts with the first administrator, enabled and not locked, as the only user. The
 * signing key is the one the service created when it started.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
public abstract class IntegrationTest {

  protected static final String ADMIN = "admin";
  protected static final String ADMIN_PASSWORD = "Admin-test-2026";
  protected static final String KEY_ENCRYPTION_SECRET = "key-encryption-test-secret";
  protected static final String ACCOUNT_SERVICE_SECRET = "account-service-test-secret";
  protected static final String CREDIT_SERVICE_SECRET = "credit-service-test-secret";
  protected static final String PASSWORD = "Clave-de-ana-2026";

  protected static final String DATABASE = "auth_db";
  protected static final PostgreSQLContainer POSTGRES =
      new PostgreSQLContainer("postgres:16-alpine").withDatabaseName(DATABASE);
  protected static final StubConfigServer CONFIG_SERVER;
  protected static final TestVault VAULT;

  static {
    POSTGRES.start();
    // Read by application.yaml through VAULT_URI and VAULT_APPROLE_FILE.
    VAULT =
        TestVault.start(
            "auth-service",
            Map.of(
                "spring.r2dbc.username",
                POSTGRES.getUsername(),
                "spring.r2dbc.password",
                POSTGRES.getPassword(),
                "spring.flyway.user",
                POSTGRES.getUsername(),
                "spring.flyway.password",
                POSTGRES.getPassword(),
                "auth.bootstrap.admin-password",
                ADMIN_PASSWORD,
                "auth.jwt.key-encryption-secret",
                KEY_ENCRYPTION_SECRET,
                "auth.service-clients.account-service",
                ACCOUNT_SERVICE_SECRET,
                "auth.service-clients.credit-service",
                CREDIT_SERVICE_SECRET));
    Map<String, String> properties = new HashMap<>(yaml("stub-config/auth-service.yml"));
    properties.put(
        "spring.r2dbc.url",
        "r2dbc:postgresql://"
            + POSTGRES.getHost()
            + ":"
            + POSTGRES.getMappedPort(5432)
            + "/"
            + DATABASE);
    properties.put("spring.flyway.url", POSTGRES.getJdbcUrl());
    // No registry in the tests: the service must not register with a real Eureka.
    properties.put("eureka.client.enabled", "false");
    CONFIG_SERVER = StubConfigServer.start(properties);
    // Read by application.yaml: configserver:${CONFIG_SERVER_URL:http://localhost:8888}
    System.setProperty("CONFIG_SERVER_URL", CONFIG_SERVER.url());
  }

  @Autowired protected WebTestClient webTestClient;

  @Autowired protected DatabaseClient databaseClient;

  @BeforeEach
  void startClean() {
    databaseClient
        .sql("DELETE FROM users WHERE username <> :admin")
        .bind("admin", ADMIN)
        .then()
        .block();
    databaseClient
        .sql(
            "UPDATE users SET status = 'ACTIVE', failed_attempts = 0, locked_until = NULL"
                + " WHERE username = :admin")
        .bind("admin", ADMIN)
        .then()
        .block();
    webTestClient = webTestClient.mutate().responseTimeout(Duration.ofSeconds(15)).build();
  }

  private static Map<String, String> yaml(String resource) {
    YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
    factory.setResources(new ClassPathResource(resource));
    Properties loaded = factory.getObject();
    Map<String, String> properties = new HashMap<>();
    loaded.forEach((key, value) -> properties.put(key.toString(), value.toString()));
    return properties;
  }

  // ----- requests

  protected static Map<String, Object> credentials(String username, String password) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("username", username);
    body.put("password", password);
    return body;
  }

  protected static Map<String, Object> client(String clientId, String clientSecret) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("clientId", clientId);
    body.put("clientSecret", clientSecret);
    return body;
  }

  /** A valid request to create a user with the password {@link #PASSWORD}. */
  protected static Map<String, Object> newUser(String username, String... roles) {
    Map<String, Object> body = credentials(username, PASSWORD);
    body.put("roles", List.of(roles));
    return body;
  }

  protected WebTestClient.ResponseSpec post(String path, Object body) {
    return webTestClient
        .post()
        .uri(path)
        .contentType(MediaType.APPLICATION_JSON)
        .bodyValue(body)
        .exchange();
  }

  protected WebTestClient.ResponseSpec login(String username, String password) {
    return post("/api/v1/auth/login", credentials(username, password));
  }

  protected WebTestClient.ResponseSpec serviceToken(String clientId, String clientSecret) {
    return post("/api/v1/auth/service-token", client(clientId, clientSecret));
  }

  protected WebTestClient.ResponseSpec createUser(Object body) {
    return post("/api/v1/auth/users", body);
  }

  /** Creates a user with the password {@link #PASSWORD} and returns it. */
  protected UserResponse created(String username, String... roles) {
    return createUser(newUser(username, roles))
        .expectStatus()
        .isCreated()
        .expectBody(UserResponse.class)
        .returnResult()
        .getResponseBody();
  }

  /** Logs in and returns the token response. */
  protected TokenResponse loggedIn(String username, String password) {
    return login(username, password)
        .expectStatus()
        .isOk()
        .expectBody(TokenResponse.class)
        .returnResult()
        .getResponseBody();
  }

  protected String jwkSet() {
    return webTestClient
        .get()
        .uri("/api/v1/auth/jwks")
        .exchange()
        .expectStatus()
        .isOk()
        .expectBody(String.class)
        .returnResult()
        .getResponseBody();
  }

  protected WebTestClient.ResponseSpec userAction(Object userId, String action) {
    return webTestClient
        .post()
        .uri("/api/v1/auth/users/{userId}/{action}", userId, action)
        .exchange();
  }

  /** Checks an error answer: status, code and the path of the request. */
  protected static WebTestClient.BodyContentSpec expectError(
      WebTestClient.ResponseSpec response, int status, String code) {
    return response
        .expectStatus()
        .isEqualTo(status)
        .expectBody()
        .jsonPath("$.code")
        .isEqualTo(code)
        .jsonPath("$.message")
        .isNotEmpty()
        .jsonPath("$.timestamp")
        .isNotEmpty()
        .jsonPath("$.traceId")
        .isNotEmpty();
  }
}
