package service

import (
	"crypto/rand"
	"errors"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var ErrInvalidToken = errors.New("тухлый токен")

func CreateAccessToken(userID int64, secret string, ttl time.Duration) (string, error) {
	id := strconv.FormatInt(userID, 10)
	claims := jwt.RegisteredClaims{
		Subject:   id, // ← сюда userID строкой
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	raw, err := token.SignedString([]byte(secret))
	return raw, err
}

func CreateRefreshToken(userID int64, secret string, ttl time.Duration) (raw string, jti string, err error) {
	id := strconv.FormatInt(userID, 10)
	jti = rand.Text()
	claims := jwt.RegisteredClaims{
		ID:        jti,
		Subject:   id, // ← сюда userID строкой
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	raw, err = token.SignedString([]byte(secret))
	return raw, jti, err
}

func ParseAccessToken(raw string, secret string) (int64, error) {
	parsed := &jwt.RegisteredClaims{}
	_, err := jwt.ParseWithClaims(raw, parsed, func(t *jwt.Token) (any, error) { return []byte(secret), nil }, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return 0, ErrInvalidToken
	}
	num, err := strconv.ParseInt(parsed.Subject, 10, 64)
	if err != nil {
		return 0, ErrInvalidToken
	}
	return num, nil
}
