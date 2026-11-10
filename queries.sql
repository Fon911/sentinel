-- name: CreateUser :one
INSERT INTO users (email, password_hash)
VALUES ($1, $2)
RETURNING id;
-- name: GetUserByEmail :one
SELECT id,
  password_hash,
  totp_enabled
FROM users
WHERE email = $1;
-- name: GetEmailByID :one
SELECT email
FROM users
WHERE id = $1;
-- name: SaveTOTPSecret :exec
UPDATE users
SET totp_secret = $2
WHERE id = $1;
-- name: GetTOTPByID :one
SELECT totp_secret,
  totp_enabled
FROM users
WHERE id = $1;
-- name: SetTOTPEnabled :exec
UPDATE users
SET totp_enabled = TRUE
WHERE id = $1;