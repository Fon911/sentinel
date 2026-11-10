package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/Fon911/sentinel/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("нет такого ")
var ErrEmailTaken = errors.New("email занят")
var ErrUserNotFound = errors.New("нет такого пользователя")

func NewPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("не смог создать пул: %w", err)
	}

	return pool, nil
}

func CreateUser(ctx context.Context, pool *pgxpool.Pool, email string, passwordHash string) (int64, error) {
	q := db.New(pool)

	id, err := q.CreateUser(ctx, db.CreateUserParams{
		Email:        email,
		PasswordHash: passwordHash,
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return 0, ErrEmailTaken
	}

	if err != nil {
		return 0, fmt.Errorf("вставка упала: %w", err)
	}
	return id, nil
}

func GetUserByEmail(ctx context.Context, pool *pgxpool.Pool, email string) (id int64, hash string, enabled bool, err error) {
	q := db.New(pool)
	row, err := q.GetUserByEmail(ctx, email)
	// Три исхода
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, "", false, ErrUserNotFound
	}
	if err != nil {
		return 0, "", false, fmt.Errorf("база сломалась: %w", err) // настоящий сбой

	}

	return row.ID, row.PasswordHash, row.TotpEnabled, nil
}

func GetEmailByID(ctx context.Context, pool *pgxpool.Pool, id int64) (string, error) {
	q := db.New(pool)
	email, err := q.GetEmailByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrUserNotFound
	}
	if err != nil {
		return "", fmt.Errorf("база сломалась: %w", err) // настоящий сбой

	}
	return email, nil

}

func SaveTOTPSecret(ctx context.Context, pool *pgxpool.Pool, id int64, secret string) error {
	q := db.New(pool)
	err := q.SaveTOTPSecret(ctx, db.SaveTOTPSecretParams{
		ID:         id,
		TotpSecret: pgtype.Text{String: secret, Valid: true},
	})
	if err != nil {
		return fmt.Errorf("сохранение секрета упало: %w", err)
	}
	return nil
}

func GetTOTP(ctx context.Context, pool *pgxpool.Pool, id int64) (secret string, enabled bool, err error) {
	q := db.New(pool)
	row, err := q.GetTOTPByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, ErrUserNotFound
	}
	if err != nil {
		return "", false, fmt.Errorf("база сломалась: %w", err) // настоящий сбой

	}
	return row.TotpSecret.String, row.TotpEnabled, nil
}

func SetTOTPEnabled(ctx context.Context, pool *pgxpool.Pool, id int64) error {
	q := db.New(pool)
	err := q.SetTOTPEnabled(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUserNotFound
	}
	if err != nil {
		return fmt.Errorf("база сломалась: %w", err) // настоящий сбой

	}
	return nil
}
