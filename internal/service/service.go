package service

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/Fon911/sentinel/internal/storage"
	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

var ErrWeakPassword = errors.New("пароль короче 8 - отказ")
var ErrEmailTaken = storage.ErrEmailTaken
var ErrTokenReused = errors.New("Токен переиспользуеться те украден")

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

var ErrInvalidCredentials = errors.New("неверный email или пароль")

const (
	accessTTL  = 15 * time.Minute
	refreshTTL = 7 * 24 * time.Hour
)

func Login(ctx context.Context, pool *pgxpool.Pool, rdb *redis.Client, email, password, secret string) (string, string, error) {
	id, hash, err := storage.GetUserByEmail(ctx, pool, email)
	if errors.Is(err, storage.ErrUserNotFound) {
		return "", "", ErrInvalidCredentials
	}
	if err != nil {
		return "", "", err
	}
	match, err := argon2id.ComparePasswordAndHash(password, hash)
	if err != nil {
		return "", "", err
	}
	if !match {
		return "", "", ErrInvalidCredentials
	}

	token, err := CreateAccessToken(id, secret, accessTTL)
	if err != nil {
		return "", "", err
	}
	refresh, jti, err := CreateRefreshToken(id, secret, refreshTTL)
	if err != nil {
		return "", "", err
	}
	err = rdb.Set(ctx, "refresh:"+jti, id, refreshTTL).Err()
	if err != nil {
		return "", "", err
	}
	indexKey := "sessions:" + strconv.FormatInt(id, 10)
	err = rdb.SAdd(ctx, indexKey, jti).Err()
	if err != nil {
		return "", "", err
	}
	err = rdb.Expire(ctx, indexKey, refreshTTL).Err()
	if err != nil {
		return "", "", err
	}
	return token, refresh, nil
}

func Refresh(ctx context.Context, rdb *redis.Client, raw, secret string) (string, string, error) {
	userID, jti, err := ParseRefreshToken(raw, secret)
	if err != nil {
		return "", "", err
	}
	indexKey := "sessions:" + strconv.FormatInt(userID, 10)
	err = rdb.Get(ctx, "refresh:"+jti).Err()
	if errors.Is(err, redis.Nil) {
		jtis, err := rdb.SMembers(ctx, indexKey).Result()
		if err != nil {
			return "", "", err
		}
		for _, j := range jtis {
			err = rdb.Del(ctx, "refresh:"+j).Err()
			if err != nil {
				return "", "", err
			}
		}
		err = rdb.Del(ctx, indexKey).Err()
		if err != nil {
			return "", "", err
		}
		return "", "", ErrTokenReused
	} else if err != nil {
		return "", "", err

	}

	err = rdb.Del(ctx, "refresh:"+jti).Err()
	if err != nil {
		return "", "", err
	}
	err = rdb.SRem(ctx, indexKey, jti).Err()
	if err != nil {
		return "", "", err
	}
	newAccessToken, err := CreateAccessToken(userID, secret, accessTTL)
	if err != nil {
		return "", "", err
	}
	newRefreshToken, jti, err := CreateRefreshToken(userID, secret, refreshTTL)
	if err != nil {
		return "", "", err
	}
	err = rdb.Set(ctx, "refresh:"+jti, userID, refreshTTL).Err()
	if err != nil {
		return "", "", err
	}
	err = rdb.SAdd(ctx, indexKey, jti).Err()
	if err != nil {
		return "", "", err
	}
	err = rdb.Expire(ctx, indexKey, refreshTTL).Err()
	if err != nil {
		return "", "", err
	}
	return newAccessToken, newRefreshToken, nil
}

func Logout(ctx context.Context, rdb *redis.Client, raw, secret string) error {
	userID, jti, err := ParseRefreshToken(raw, secret)
	if err != nil {
		return ErrInvalidToken
	}
	indexKey := "sessions:" + strconv.FormatInt(userID, 10)
	err = rdb.Del(ctx, "refresh:"+jti).Err()
	if err != nil {
		return err
	}
	err = rdb.SRem(ctx, indexKey, jti).Err()
	if err != nil {
		return err
	}

	return nil
}
