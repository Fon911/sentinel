package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Fon911/sentinel/internal/storage"
	"github.com/go-chi/chi/v5"
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
				t.Errorf("статус: got %d, want 201; тело: %s", rec.Code, rec.Body.String())
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

func setupPool(t *testing.T) {
	t.Helper()
	if Pool != nil {
		return
	}

	pool, err := storage.NewPool(context.Background(), "postgres://postgres:secret@localhost:5401/postgres")
	if err != nil {
		t.Fatalf("база недоступна (docker start sentineldb?): %v", err)
	}
	Pool = pool

}
