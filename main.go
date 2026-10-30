package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/Fon911/sentinel/internal/handler"
	"github.com/Fon911/sentinel/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/redis/go-redis/v9"
)

func main() {
	rt := chi.NewRouter()
	rt.Post("/auth/register", handler.Register)
	rt.Get("/health", handler.Health)
	rt.Group(func(r chi.Router) {
		r.Use(handler.AuthMiddleware)
		r.Get("/me", handler.Me)
	})
	rt.Post("/auth/refresh", handler.Refresh)
	rt.Post("/auth/logout", handler.Logout)

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres:secret@localhost:5401/postgres"
	}
	pool, err := storage.NewPool(context.Background(), dsn)

	if err != nil {
		fmt.Println(err)
		return
	}
	handler.Pool = pool
	defer pool.Close()
	fmt.Println("база подключена")
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		fmt.Println("редис недоступен:", err)
		return
	}
	handler.RDB = rdb
	rt.Post("/auth/login", handler.Login)
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "dev-only-secret"
	}

	handler.Secret = secret
	err = http.ListenAndServe(":8000", rt)
	if err != nil {
		fmt.Println(err)
	}
}
