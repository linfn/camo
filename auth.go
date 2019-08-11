package camo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

// WithAuth ...
func WithAuth(h http.Handler, password string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, mac, ok := r.BasicAuth()
		if !ok {
			http.NotFound(w, r)
			return
		}
		if userMac(user, password) != mac {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// SetAuth ...
func SetAuth(r *http.Request, password string) {
	if r.Header == nil {
		r.Header = http.Header{}
	}
	r.SetBasicAuth("camo", userMac("camo", password))
}

func userMac(user string, password string) string {
	m := hmac.New(sha256.New, []byte(password))
	m.Write([]byte(user))
	return hex.EncodeToString(m.Sum(nil))
}
