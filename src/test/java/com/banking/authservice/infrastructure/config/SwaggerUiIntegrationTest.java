package com.banking.authservice.infrastructure.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.banking.authservice.support.IntegrationTest;
import org.junit.jupiter.api.Test;

/** Swagger UI shows the contract the code is generated from. */
class SwaggerUiIntegrationTest extends IntegrationTest {

  @Test
  void theContractIsServedAsItIsWritten() {
    webTestClient
        .get()
        .uri(OpenApiContractConfiguration.CONTRACT_PATH)
        .exchange()
        .expectStatus()
        .isOk()
        .expectBody(String.class)
        .value(
            contract ->
                assertThat(contract)
                    .contains("/api/v1/auth/login")
                    .contains("/api/v1/auth/jwks")
                    .contains("operationId: login")
                    .contains("operationId: issueServiceToken"));
  }

  @Test
  void swaggerUiPointsAtTheContract() {
    webTestClient
        .get()
        .uri("/v3/api-docs/swagger-config")
        .exchange()
        .expectStatus()
        .isOk()
        .expectBody()
        .jsonPath("$.url")
        .isEqualTo(OpenApiContractConfiguration.CONTRACT_PATH);
  }
}
