-- api_keys: stores hashed API keys for authenticated access.
--
-- The plaintext key is shown to the operator only at creation time and is
-- never logged or stored. The key_hash is SHA-256 of the bearer token that
-- clients send in the Authorization: Bearer <key> header.
--
-- When AUTH_ENABLED is true, every endpoint except /health requires a
-- valid, non-revoked API key. A bootstrap key can be seeded via the
-- ADMIN_API_KEY env var at startup if the table is empty.
CREATE TABLE IF NOT EXISTS api_keys (
    id          BIGSERIAL   PRIMARY KEY,
    name        TEXT        NOT NULL,
    key_hash    BYTEA       NOT NULL UNIQUE,
    prefix      TEXT        NOT NULL, -- first 8 chars of the plaintext key for identification
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked     BOOLEAN     NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys (key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_revoked ON api_keys (revoked) WHERE revoked = false;

COMMENT ON TABLE api_keys IS 'API keys for authenticated access mode.';
COMMENT ON COLUMN api_keys.key_hash IS 'SHA-256 hash of the bearer token.';
COMMENT ON COLUMN api_keys.prefix IS 'First 8 characters of the plaintext key, for identification in listings.';
COMMENT ON COLUMN api_keys.revoked IS 'When true, the key is rejected by the auth middleware.';
