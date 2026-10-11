package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/Fon911/sentinel/internal/handler"
	"github.com/Fon911/sentinel/internal/storage"
	"github.com/go-chi/chi/v5"
)

func main() {
	rt := chi.NewRouter()
	rt.Post("/auth/register", handler.Register)
	rt.Get("/health", handler.Health)

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

	err = http.ListenAndServe(":8000", rt)
	if err != nil {
		fmt.Println(err)
	}
}
