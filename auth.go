package camo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
)

const (
	camoAuthTypeHMAC = "CAMO-HMAC"
	camoAuthText     = "camo"
)

// WithAuth ...
func WithAuth(h http.Handler, password string, log Logger) http.Handler {
	if log == nil {
		log = (*LevelLogger)(nil) // log nothing
	}
	var (
		wanted  = hmacSha256(camoAuthText, password)
		invalid = make([]byte, len(wanted))
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mac, ok := GetAuth(r)
		if ok {
			if len(mac) != len(wanted) {
				mac = invalid
				ok = false
			}
		} else {
			mac = invalid
		}
		// constant time compare
		if !hmac.Equal(wanted, mac) {
			ok = false
		}
		if !ok {
			http.NotFound(w, r)
			log.Infof("auth declined. %s %s, remote: %s", r.Method, r.URL, r.RemoteAddr)
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
	mac := hmacSha256(camoAuthText, password)
	r.Header.Set("Authorization", camoAuthTypeHMAC+" "+base64.StdEncoding.EncodeToString(mac))
}

// GetAuth ...
func GetAuth(r *http.Request) (mac []byte, ok bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return
	}
	const prefix = camoAuthTypeHMAC + " "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return
	}
	mac, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	return mac, true
}

func hmacSha256(text string, password string) []byte {
	m := hmac.New(sha256.New, []byte(password))
	m.Write([]byte(text))
	return m.Sum(nil)
}
