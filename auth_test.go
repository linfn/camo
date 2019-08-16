package camo

import (
	"crypto/subtle"
	"net/http"
	"testing"
)

func TestAuth(t *testing.T) {
	r := &http.Request{}
	SetAuth(r, "123456")

	text, mac, ok := GetAuth(r)
	if !ok {
		t.Fatal()
	}
	if subtle.ConstantTimeCompare(mac, HmacSha256(text, "123456")) != 1 {
		t.Fatal()
	}
	if subtle.ConstantTimeCompare(mac, HmacSha256(text, "111111")) == 1 {
		t.Fatal()
	}
}
