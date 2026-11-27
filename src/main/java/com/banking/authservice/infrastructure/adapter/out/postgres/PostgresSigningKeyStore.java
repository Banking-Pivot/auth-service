package com.banking.authservice.infrastructure.adapter.out.postgres;

import static org.springframework.data.relational.core.query.Criteria.where;
import static org.springframework.data.relational.core.query.Query.query;

import com.banking.authservice.infrastructure.adapter.out.security.SigningKeyStore;
import com.banking.authservice.infrastructure.adapter.out.security.StoredSigningKey;
import org.springframework.data.r2dbc.core.R2dbcEntityTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/** Keeps the signing key in PostgreSQL through Spring Data, with no SQL written by hand. */
@Component
public class PostgresSigningKeyStore implements SigningKeyStore {

  private static final String ONE_KEY = "uk_signing_keys_purpose";

  private final R2dbcEntityTemplate template;

  public PostgresSigningKeyStore(R2dbcEntityTemplate template) {
    this.template = template;
  }

  @Override
  public Mono<StoredSigningKey> find() {
    return template
        .selectOne(query(where("purpose").is(SigningKeyRow.ACCESS_TOKEN)), SigningKeyRow.class)
        .map(SigningKeyRow::toStoredKey);
  }

  @Override
  public Mono<Boolean> insert(StoredSigningKey key) {
    return template
        .insert(SigningKeyRow.of(key))
        .thenReturn(true)
        .onErrorReturn(error -> PostgresErrors.isUniqueViolation(error, ONE_KEY), false);
  }

  @Override
  public Mono<Void> delete(String keyId) {
    return template.delete(query(where("keyId").is(keyId)), SigningKeyRow.class).then();
  }
}
