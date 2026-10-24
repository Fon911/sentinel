package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Fon911/sentinel/internal/service"
	"github.com/Fon911/sentinel/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/redis/go-redis/v9"
)

func TestRegister(t *testing.T) {
	uniq := fmt.Sprintf(`{"email":"u%d@test.io","password":"longenough1"}`, time.Now().UnixNano())

	tests := []struct {
		body string
		code int
	}{
		{uniq, 201},
		{`musor`, 400},
		{`{"email":"","password":"longenough1"}`, 400},
		{`{"email":"short@test.io","password":"short"}`, 400},
	}
	setupPool(t)
	rt := chi.NewRouter()
	rt.Post("/auth/register", Register)

	for _, tc := range tests {

		t.Run(tc.body, func(t *testing.T) {

			body := strings.NewReader(tc.body)
			req := httptest.NewRequest(http.MethodPost, "/auth/register", body)
			rec := httptest.NewRecorder()

			rt.ServeHTTP(rec, req)

			if rec.Code != tc.code {
				t.Errorf("статус: got %d, want %d; тело: %s", rec.Code, tc.code, rec.Body.String())

			}
			if tc.code == 201 {
				if !strings.Contains(rec.Body.String(), `"id"`) {
					t.Errorf("в ответе нет id: %s", rec.Body.String())
				}
			}
		})
	}
	t.Run("дубль email", func(t *testing.T) {
		dup := fmt.Sprintf(`{"email":"dup%d@test.io","password":"longenough1"}`, time.Now().UnixNano())
		req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(dup))
		rec := httptest.NewRecorder()

		rt.ServeHTTP(rec, req)

		if rec.Code != 201 {
			t.Errorf("статус: got %d, want 201; тело: %s", rec.Code, rec.Body.String())
		}

		req = httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(dup))
		rec = httptest.NewRecorder()
		rt.ServeHTTP(rec, req)
		if rec.Code != 409 {
			t.Errorf("статус: got %d, want 409; тело: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestLogin(t *testing.T) {
	setupPool(t)

	email := fmt.Sprintf("u%d@test.io", time.Now().UnixNano())
	_, err := service.Register(context.Background(), Pool, email, "longenough1")
	if err != nil {
		t.Fatalf("подготовка: %v", err)
	}

	okBody := fmt.Sprintf(`{"email":%q,"password":"longenough1"}`, email)
	badPassBody := fmt.Sprintf(`{"email":%q,"password":"wrongwrong1"}`, email)
	tests := []struct {
		body string
		code int
	}{
		{okBody, 200},
		{badPassBody, 401},
		{`{"email":"ghost@test.io","password":"longenough1"}`, 401},
		{`musor`, 400},
	}
	rt := chi.NewRouter()
	rt.Post("/auth/login", Login)
	for _, tc := range tests {

		t.Run(tc.body, func(t *testing.T) {

			body := strings.NewReader(tc.body)
			req := httptest.NewRequest(http.MethodPost, "/auth/login", body)
			rec := httptest.NewRecorder()

			rt.ServeHTTP(rec, req)

			if rec.Code != tc.code {
				t.Errorf("статус: got %d, want %d; тело: %s", rec.Code, tc.code, rec.Body.String())
			}
			if tc.code == 200 {
				if !strings.Contains(rec.Body.String(), `"access_token"`) {
					t.Errorf("в ответе нет access_token: %s", rec.Body.String())
				}
				if !strings.Contains(rec.Body.String(), `"refresh_token"`) {
					t.Errorf("в ответе нет refresh_token: %s", rec.Body.String())
				}

			}
		})
	}

}

func setupPool(t *testing.T) {
	t.Helper()
	if Pool != nil {
		return
	}
	Secret = "test-secret"

	RDB = redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	if err := RDB.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("редис недоступен (docker compose up -d?): %v", err)
	}

	pool, err := storage.NewPool(context.Background(), "postgres://postgres:secret@localhost:5401/postgres")
	if err != nil {
		t.Fatalf("база недоступна (docker start sentineldb?): %v", err)
	}
	Pool = pool

}
