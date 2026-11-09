package service

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/Fon911/sentinel/internal/storage"
	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
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
var ErrTooManyAttempts = errors.New("слишком много попыток, подожди 15 минут")

const (
	accessTTL  = 15 * time.Minute
	refreshTTL = 7 * 24 * time.Hour
)

func addFailedAttempt(ctx context.Context, rdb *redis.Client, key string) error {
	n, err := rdb.Incr(ctx, key).Result()
	if err != nil {
		return err
	}
	if n == 1 {
		if err := rdb.Expire(ctx, key, time.Minute*15).Err(); err != nil {
			return err
		}
	}
	return nil
}

func Login(ctx context.Context, pool *pgxpool.Pool, rdb *redis.Client, email, password, secret string) (string, string, error) {
	key := "login_attempts:" + email
	n, err := rdb.Get(ctx, key).Int()
	if errors.Is(err, redis.Nil) {
		// полки нет — неудач не было, едем дальше
	} else if err != nil {
		return "", "", err
	}
	if n >= 5 {
		return "", "", ErrTooManyAttempts
	}
	id, hash, err := storage.GetUserByEmail(ctx, pool, email)
	if errors.Is(err, storage.ErrUserNotFound) {
		if err := addFailedAttempt(ctx, rdb, key); err != nil {
			return "", "", err
		}
		return "", "", ErrInvalidCredentials
	}
	match, err := argon2id.ComparePasswordAndHash(password, hash)
	if err != nil {
		return "", "", err
	}
	if !match {
		if err := addFailedAttempt(ctx, rdb, key); err != nil {
			return "", "", err
		}
		return "", "", ErrInvalidCredentials
	}
	err = rdb.Del(ctx, key).Err()
	if err != nil {
		return "", "", err
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

func Setup2FA(ctx context.Context, pool *pgxpool.Pool, userID int64) (*otp.Key, error) {
	email, err := storage.GetEmailByID(ctx, pool, userID)
	if err != nil {
		return nil, err
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Sentinel",
		AccountName: email,
	})
	if err != nil {
		return nil, err
	}
	err = storage.SaveTOTPSecret(ctx, pool, userID, key.Secret())
	if err != nil {
		return nil, err
	}
	return key, nil
}
