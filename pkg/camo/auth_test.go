package camo

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuth(t *testing.T) {
	const wantPassword = "123456"
	auth := func(password string) int {
		var (
			r http.Request
			w = httptest.NewRecorder()
		)
		if password != "" {
			SetAuth(&r, password)
		}
		WithAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), wantPassword, nil).ServeHTTP(w, &r)
		return w.Code
	}

	if auth(wantPassword) != 200 {
		t.Error()
	}
	if auth(wantPassword+"1") != 404 {
		t.Error()
	}
	if auth("") != 404 {
		t.Error()
	}
}
