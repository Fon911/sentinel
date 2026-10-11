package service

import (
	"context"
	"errors"

	"github.com/Fon911/sentinel/internal/storage"
	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrWeakPassword = errors.New("пароль короче 8 - отказ")
var ErrEmailTaken = storage.ErrEmailTaken

func Register(ctx context.Context, pool *pgxpool.Pool, email string, password string) (int64, error) {
	if len(password) < 8 {
		return 0, ErrWeakPassword
	}
	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return 0, err
	}
	id, err := storage.CreateUser(ctx, pool, email, hash)
	if err != nil {
		return 0, err
	}

	return id, nil

}
