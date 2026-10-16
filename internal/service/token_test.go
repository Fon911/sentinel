package service

import (
	"testing"
	"time"
)

func TestAccessToken(t *testing.T) {

	t.Run("валидный", func(t *testing.T) {
		raw, err := CreateAccessToken(42, "s", time.Minute)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		id, err := ParseAccessToken(raw, "s")
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if id != 42 {
			t.Errorf("id: got %d, want 42", id)
		}
	})
	t.Run("протухший", func(t *testing.T) {
		raw, err := CreateAccessToken(42, "s", -time.Minute)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		_, err = ParseAccessToken(raw, "s")
		if err == nil {
			t.Errorf("ждал протухание, а токен прошёл")
		}

	})
	t.Run("чужой секрет", func(t *testing.T) {
		raw, err := CreateAccessToken(42, "s", time.Minute)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		_, err = ParseAccessToken(raw, "wrong")
		if err == nil {
			t.Errorf("ждал чужой сикрет, а токен прошёл")
		}

	})
	t.Run("Мусор", func(t *testing.T) {
		_, err := ParseAccessToken("musor", "s")
		if err == nil {
			t.Errorf("ждал мусор, а токен прошёл")
		}

	})
}
