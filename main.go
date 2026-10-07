package main

import (
	"fmt"
	"net/http"

	"github.com/Fon911/sentinel/internal/handler"
	"github.com/go-chi/chi/v5"
)

func main() {
	rt := chi.NewRouter()

	rt.Get("/health", handler.Health)
	err := http.ListenAndServe(":8000", rt)
	if err != nil {
		fmt.Println(err)
	}
}
