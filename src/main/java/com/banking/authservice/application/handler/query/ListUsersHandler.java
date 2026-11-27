package com.banking.authservice.application.handler.query;

import com.banking.authservice.application.model.ResultPage;
import com.banking.authservice.application.port.in.ListUsersUseCase;
import com.banking.authservice.application.port.out.UserStorePort;
import com.banking.authservice.application.query.PageRequest;
import com.banking.authservice.domain.model.User;
import reactor.core.publisher.Mono;

/** Lists the users. */
public class ListUsersHandler implements ListUsersUseCase {

  private final UserStorePort users;

  public ListUsersHandler(UserStorePort users) {
    this.users = users;
  }

  @Override
  public Mono<ResultPage<User>> execute(PageRequest pageRequest) {
    return users.findPage(pageRequest);
  }
}
