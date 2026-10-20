-- name: CreateUser :one
INSERT INTO users (email, password_hash)
VALUES ($1, $2)
RETURNING id;
-- name: GetUserByEmail :one
SELECT id,
  password_hash
FROM users
WHERE email = $1;