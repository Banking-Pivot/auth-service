package com.banking.authservice.infrastructure.startup;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.banking.authservice.application.port.in.EnsureAdministratorUseCase;
import com.banking.authservice.application.port.in.GetVerificationKeysUseCase;
import com.banking.authservice.domain.model.vo.VerificationKey;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import reactor.core.publisher.Mono;

@ExtendWith({MockitoExtension.class, OutputCaptureExtension.class})
class AuthStartupTest {

  @Mock private GetVerificationKeysUseCase verificationKeys;
  @Mock private EnsureAdministratorUseCase ensureAdministrator;
  @InjectMocks private AuthStartup startup;

  @Test
  void theKeyIsLoadedAndTheFirstAdministratorCreated(CapturedOutput output) {
    when(verificationKeys.execute())
        .thenReturn(Mono.just(List.of(new VerificationKey("key-1", "modulus", "AQAB"))));
    when(ensureAdministrator.execute()).thenReturn(Mono.just(true));

    startup.run(new DefaultApplicationArguments());

    assertThat(output.getOut())
        .contains("Signing key ready. keyIds=[key-1]", "First administrator created.")
        .doesNotContain("modulus");
  }

  @Test
  void anAdministratorThatAlreadyExistsIsNotAnnounced(CapturedOutput output) {
    when(verificationKeys.execute()).thenReturn(Mono.just(List.of()));
    when(ensureAdministrator.execute()).thenReturn(Mono.just(false));

    startup.run(new DefaultApplicationArguments());

    assertThat(output.getOut()).doesNotContain("First administrator created.");
  }

  @Test
  void aServiceThatCannotLoadItsKeyDoesNotStart() {
    when(verificationKeys.execute())
        .thenReturn(Mono.error(new IllegalStateException("database unreachable")));

    assertThatThrownBy(() -> startup.run(new DefaultApplicationArguments()))
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("database unreachable");
    verify(ensureAdministrator, never()).execute();
  }
}
