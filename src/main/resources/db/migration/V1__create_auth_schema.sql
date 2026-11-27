-- Auth Service keeps the users of the platform and the key that signs their access tokens.
-- Instants are TIMESTAMPTZ and the application writes them in UTC. Enum columns are VARCHAR
-- with CHECK constraints.

-- One row per user. The username is stored in lower case, so the unique constraint also
-- makes "Ana" and "ana" the same user. The password is only kept as a BCrypt hash.
CREATE TABLE users (
    id             UUID         NOT NULL,
    username       VARCHAR(50)  NOT NULL,
    password_hash  VARCHAR(100) NOT NULL,
    -- Role names in alphabetical order, separated by commas.
    roles          VARCHAR(20)  NOT NULL,
    status         VARCHAR(20)  NOT NULL,
    created_at     TIMESTAMPTZ  NOT NULL,
    updated_at     TIMESTAMPTZ  NOT NULL,
    CONSTRAINT pk_users PRIMARY KEY (id),
    CONSTRAINT uk_users_username UNIQUE (username),
    CONSTRAINT ck_users_username CHECK (username = lower(username)),
    CONSTRAINT ck_users_roles CHECK (roles IN ('ADMIN', 'USER', 'ADMIN,USER')),
    CONSTRAINT ck_users_status CHECK (status IN ('ACTIVE', 'DISABLED'))
);

-- The RSA key pair that signs the access tokens. It is created the first time the service
-- starts and read on every later start, so a restart does not invalidate the tokens in use.
-- The private key is stored encrypted (AES-GCM) under a secret that only lives in Vault; the
-- public key is what GET /api/v1/auth/jwks publishes. The unique purpose keeps a single key
-- when two instances start at the same time: the second one finds the first one's key.
CREATE TABLE signing_keys (
    key_id                 VARCHAR(64) NOT NULL,
    purpose                VARCHAR(20) NOT NULL,
    -- Both in base64: the public key X.509 encoded; the private key as it was encrypted.
    public_key             TEXT        NOT NULL,
    encrypted_private_key  TEXT        NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL,
    CONSTRAINT pk_signing_keys PRIMARY KEY (key_id),
    CONSTRAINT uk_signing_keys_purpose UNIQUE (purpose),
    CONSTRAINT ck_signing_keys_purpose CHECK (purpose IN ('ACCESS_TOKEN'))
);
