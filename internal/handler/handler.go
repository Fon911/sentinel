package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/Fon911/sentinel/internal/service"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

var Pool *pgxpool.Pool
var RDB *redis.Client
var Secret string

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
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type MeResponse struct {
	ID int64 `json:"id"`
}
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func Me(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(userIDKey).(int64)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(MeResponse{ID: userID})
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

func Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
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
	access, refresh, err := service.Login(r.Context(), Pool, RDB, req.Email, req.Password, Secret)
	if errors.Is(err, service.ErrInvalidCredentials) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "неверный пароль или email")
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "ошибка сервера")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(LoginResponse{AccessToken: access, RefreshToken: refresh})

}

func Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	err := json.NewDecoder(r.Body).Decode(&req)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "кривой JSON")
		return
	}
	if req.RefreshToken == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "нужно поле refresh-токен")
		return
	}
	access, refresh, err := service.Refresh(r.Context(), RDB, req.RefreshToken, Secret)
	if errors.Is(err, service.ErrInvalidToken) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "невалидный refresh-токен")
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "ошибка сервера")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(LoginResponse{AccessToken: access, RefreshToken: refresh})

}
