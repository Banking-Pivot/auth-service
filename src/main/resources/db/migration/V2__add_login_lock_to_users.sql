-- Lock after too many wrong passwords. failed_attempts counts the wrong passwords in a row
-- since the last correct login; locked_until is set when the count reaches the limit and
-- until that instant every login of the user is refused. Users that already exist start
-- with no failed attempts and no lock.
ALTER TABLE users
    ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN locked_until    TIMESTAMPTZ,
    ADD CONSTRAINT ck_users_failed_attempts CHECK (failed_attempts >= 0);
