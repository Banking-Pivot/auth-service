package com.banking.authservice.application.port.in;

import com.banking.authservice.application.model.ResultPage;
import com.banking.authservice.application.query.PageRequest;
import com.banking.authservice.domain.model.User;
import reactor.core.publisher.Mono;

/** Lists the users, ordered by username. */
public interface ListUsersUseCase {

  Mono<ResultPage<User>> execute(PageRequest pageRequest);
}
