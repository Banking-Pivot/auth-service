package com.banking.authservice.infrastructure.adapter.out.postgres;

import static org.springframework.data.relational.core.query.Criteria.where;
import static org.springframework.data.relational.core.query.Query.query;

import com.banking.authservice.application.exception.UsernameAlreadyExistsException;
import com.banking.authservice.application.model.ResultPage;
import com.banking.authservice.application.port.out.UserStorePort;
import com.banking.authservice.application.query.PageRequest;
import com.banking.authservice.domain.model.Role;
import com.banking.authservice.domain.model.User;
import com.banking.authservice.domain.model.UserStatus;
import java.util.UUID;
import org.springframework.data.domain.Sort;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.data.relational.core.query.Criteria;
import org.springframework.data.relational.core.query.Query;
import org.springframework.data.relational.core.query.Update;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/** Keeps users in PostgreSQL through Spring Data, with no SQL written by hand. */
@Component
public class PostgresUserAdapter implements UserStorePort {

  private static final String UNIQUE_USERNAME = "uk_users_username";
  private static final String ID = "id";
  private static final String FAILED_ATTEMPTS = "failedAttempts";
  private static final String LOCKED_UNTIL = "lockedUntil";

  private final R2dbcEntityTemplate template;

  public PostgresUserAdapter(R2dbcEntityTemplate template) {
    this.template = template;
  }

  @Override
  public Mono<Void> insert(User user) {
    return template
        .insert(UserRow.of(user))
        .then()
        .onErrorMap(
            error -> PostgresErrors.isUniqueViolation(error, UNIQUE_USERNAME),
            UsernameAlreadyExistsException::new);
  }

  @Override
  public Mono<User> findById(UUID userId) {
    return template.selectOne(query(where(ID).is(userId)), UserRow.class).map(UserRow::toUser);
  }

  @Override
  public Mono<User> findByUsername(String username) {
    return template
        .selectOne(query(where("username").is(username)), UserRow.class)
        .map(UserRow::toUser);
  }

  @Override
  public Mono<Void> updateStatus(User changed) {
    return template
        .update(UserRow.class)
        .matching(query(where(ID).is(changed.id())))
        .apply(
            Update.update("status", changed.status().name()).set("updatedAt", changed.updatedAt()))
        .then();
  }

  // The update only matches the row while it still has the failed attempts and the lock that were
  // read: of two logins that read the same row, the database lets one through and the other one
  // updates no row.
  @Override
  public Mono<Boolean> updateLoginFailures(User expected, User changed) {
    Criteria asRead =
        where(ID).is(expected.id()).and(FAILED_ATTEMPTS).is(expected.failedAttempts());
    Criteria unchanged =
        expected.lockedUntil() == null
            ? asRead.and(LOCKED_UNTIL).isNull()
            : asRead.and(LOCKED_UNTIL).is(expected.lockedUntil());
    return template
        .update(UserRow.class)
        .matching(query(unchanged))
        .apply(
            Update.update(FAILED_ATTEMPTS, changed.failedAttempts())
                .set(LOCKED_UNTIL, changed.lockedUntil()))
        .map(rows -> rows > 0);
  }

  @Override
  public Mono<Void> clearLoginFailures(UUID userId) {
    return template
        .update(UserRow.class)
        .matching(query(where(ID).is(userId)))
        .apply(Update.update(FAILED_ATTEMPTS, 0).set(LOCKED_UNTIL, null))
        .then();
  }

  // The roles column holds role names separated by commas and no role name contains another.
  @Override
  public Mono<Long> countActiveAdministrators() {
    return template.count(
        query(
            where("roles")
                .like("%" + Role.ADMIN.name() + "%")
                .and("status")
                .is(UserStatus.ACTIVE.name())),
        UserRow.class);
  }

  @Override
  public Mono<ResultPage<User>> findPage(PageRequest pageRequest) {
    return Mono.zip(
            template
                .select(
                    Query.empty()
                        .sort(Sort.by("username"))
                        .offset(pageRequest.offset())
                        .limit(pageRequest.size()),
                    UserRow.class)
                .map(UserRow::toUser)
                .collectList(),
            template.count(Query.empty(), UserRow.class))
        .map(page -> ResultPage.of(page.getT1(), pageRequest, page.getT2()));
  }
}
