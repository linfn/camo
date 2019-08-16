package camo

import (
	"net/http"
	"testing"
)

func TestAuth(t *testing.T) {
	r := &http.Request{}
	SetAuth(r, "123456")

	user, hmac, ok := GetAuth(r)
	if !ok {
		t.Fail()
	}
	if hmac != HmacSha256(user, "123456") {
		t.Fail()
	}
	if hmac == HmacSha256(user, "111111") {
		t.Fail()
	}
}
