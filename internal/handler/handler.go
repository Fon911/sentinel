package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/Fon911/sentinel/internal/service"
	"github.com/jackc/pgx/v5/pgxpool"
)

var Pool *pgxpool.Pool

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type RegisterResponse struct {
	ID int64 `json:"id"`
}
type HealthResponse struct {
	Status string `json:"status"`
}

func Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(HealthResponse{Status: "ok"})
}

func Register(w http.ResponseWriter, r *http.Request) {

	var req RegisterRequest
	err := json.NewDecoder(r.Body).Decode(&req)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "кривой JSON")
		return
	}
	if req.Email == "" || req.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "нужно поле Email или Password")
		return
	}

	id, err := service.Register(r.Context(), Pool, req.Email, req.Password)
	if errors.Is(err, service.ErrWeakPassword) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "пароль короче 8")
		return

	}
	if errors.Is(err, service.ErrEmailTaken) {
		w.WriteHeader(http.StatusConflict)
		fmt.Fprintln(w, "емейл занят")
		return

	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "не смог сохранить")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(RegisterResponse{ID: id})
}
