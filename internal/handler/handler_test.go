package handler

import (
	"context"
	"encoding/json"
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

func TestMe(t *testing.T) {
	setupPool(t)
	rt := chi.NewRouter()
	rt.Group(func(r chi.Router) {
		r.Use(AuthMiddleware)
		r.Get("/me", Me)
	})
	raw, err := service.CreateAccessToken(42, Secret, time.Minute)
	if err != nil {
		t.Fatalf("токен: %v", err)
	}

	tests := []struct {
		name   string
		header string
		code   int
	}{
		{"валидный", "Bearer " + raw, 200},
		{"без заголовка", "", 401},
		{"Bearer мусор", "Bearer Musor", 401},
	}
	for _, tc := range tests {

		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/me", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()

			rt.ServeHTTP(rec, req)

			if rec.Code != tc.code {
				t.Errorf("статус: got %d, want %d;", rec.Code, tc.code)
			}
			if tc.code == 200 {
				if !strings.Contains(rec.Body.String(), `"id":42`) {
					t.Errorf("в ответе нет id 42 - : %s", rec.Body.String())
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

func TestRefresh(t *testing.T) {
	rt := chi.NewRouter()
	setupPool(t)

	email := fmt.Sprintf("u%d@test.io", time.Now().UnixNano())
	_, err := service.Register(context.Background(), Pool, email, "longenough1")
	if err != nil {
		t.Fatalf("подготовка: %v", err)
	}
	okBody := fmt.Sprintf(`{"email":%q,"password":"longenough1"}`, email)

	body := strings.NewReader(okBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", body)
	rec := httptest.NewRecorder()
	rt.Post("/auth/login", Login)
	rt.Post("/auth/refresh", Refresh)

	rt.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("Логин не удался ")
	}
	var resp LoginResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("декод ответа: %v", err)
	}
	refreshBody := fmt.Sprintf(`{"refresh_token":%q}`, resp.RefreshToken)

	t.Run("Валидный", func(t *testing.T) {
		testReq := httptest.NewRequest(http.MethodPost, "/auth/refresh", strings.NewReader(refreshBody))
		testRec := httptest.NewRecorder()
		rt.ServeHTTP(testRec, testReq)
		if testRec.Code != 200 {
			t.Errorf("code:%d нужен 200", testRec.Code)
		}
		if testRec.Code == 200 {
			if !strings.Contains(testRec.Body.String(), `"access_token"`) {
				t.Errorf("в ответе нет access_token: %s", testRec.Body.String())
			}
			if !strings.Contains(testRec.Body.String(), `"refresh_token"`) {
				t.Errorf("в ответе нет refresh_token: %s", testRec.Body.String())
			}

		}

	})

	t.Run("Мусор", func(t *testing.T) {
		testReq := httptest.NewRequest(http.MethodPost, "/auth/refresh", strings.NewReader(`{"refresh_token":"abc"}`))
		testRec := httptest.NewRecorder()
		rt.ServeHTTP(testRec, testReq)
		if testRec.Code != 401 {
			t.Errorf("code:%d нужен 401", testRec.Code)
		}

	})

	t.Run("Повторный", func(t *testing.T) {
		testReq := httptest.NewRequest(http.MethodPost, "/auth/refresh", strings.NewReader(refreshBody))
		testRec := httptest.NewRecorder()
		rt.ServeHTTP(testRec, testReq)
		if testRec.Code != 401 {
			t.Errorf("code:%d нужен 401", testRec.Code)
		}

	})
}
