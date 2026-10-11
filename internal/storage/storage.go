package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/Fon911/sentinel/db"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("нет такого ")
var ErrEmailTaken = errors.New("email занят")

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
