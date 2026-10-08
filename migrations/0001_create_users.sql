-- +goose Up
CREATE TABLE users(
  id BIGSERIAL PRIMARY KEY,
  password_hash TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- +goose Down
DROP TABLE users;