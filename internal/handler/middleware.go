package handler

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/Fon911/sentinel/internal/service"
)

type ctxKey string

const userIDKey ctxKey = "userID"

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pass := r.Header.Get("Authorization")
		h := strings.TrimPrefix(pass, "Bearer ")
		if pass == "" || h == pass {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, "нет токена")
			return
		}
		userID, err := service.ParseAccessToken(h, Secret)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), userIDKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
