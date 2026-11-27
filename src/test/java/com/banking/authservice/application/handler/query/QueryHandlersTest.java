package com.banking.authservice.application.handler.query;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import com.banking.authservice.application.exception.UserNotFoundException;
import com.banking.authservice.application.model.ResultPage;
import com.banking.authservice.application.port.out.TokenSignerPort;
import com.banking.authservice.application.port.out.UserStorePort;
import com.banking.authservice.application.query.PageRequest;
import com.banking.authservice.domain.model.User;
import com.banking.authservice.domain.model.VerificationKey;
import com.banking.authservice.support.Users;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

@ExtendWith(MockitoExtension.class)
class QueryHandlersTest {

  @Mock private UserStorePort users;
  @Mock private TokenSignerPort signer;

  @Test
  void aStoredUserIsReturnedAndAnUnknownOneIsNotFound() {
    when(users.findById(Users.ANA_ID)).thenReturn(Mono.just(Users.ana()));
    when(users.findById(Users.ADMIN_ID)).thenReturn(Mono.empty());
    GetUserHandler handler = new GetUserHandler(users);

    assertThat(handler.execute(Users.ANA_ID).block().username()).isEqualTo("ana");
    assertThatThrownBy(() -> handler.execute(Users.ADMIN_ID).block())
        .isInstanceOf(UserNotFoundException.class)
        .hasMessageContaining(Users.ADMIN_ID.toString());
  }

  @Test
  void theListIsThePageOfTheStore() {
    PageRequest request = PageRequest.of(0, 2);
    ResultPage<User> page = ResultPage.of(List.of(Users.admin(), Users.ana()), request, 5);
    when(users.findPage(request)).thenReturn(Mono.just(page));

    assertThat(new ListUsersHandler(users).execute(request).block()).isSameAs(page);
  }

  @Test
  void theVerificationKeysAreTheOnesOfTheSigner() {
    List<VerificationKey> keys = List.of(new VerificationKey("key-1", "modulus", "AQAB"));
    when(signer.verificationKeys()).thenReturn(Mono.just(keys));

    assertThat(new GetVerificationKeysHandler(signer).execute().block()).isSameAs(keys);
  }
}
