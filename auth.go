package camo

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
)

const camoAuthTypeHMAC = "CAMO-HMAC"

// WithAuth ...
func WithAuth(h http.Handler, password string, log Logger) http.Handler {
	if log == nil {
		log = (*LevelLogger)(nil) // log nothing
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user, reqPass, ok := r.BasicAuth(); ok {
			if user != "camo" || subtle.ConstantTimeCompare([]byte(reqPass), []byte(password)) != 1 {
				http.NotFound(w, r)
				log.Infof("basic auth declined. method: %s, url: %s, remote: %s", r.Method, r.URL, r.RemoteAddr)
				return
			}
		} else {
			text, mac, ok := GetAuth(r)
			if !ok {
				http.NotFound(w, r)
				log.Infof("no auth info. method: %s, url: %s, remote: %s", r.Method, r.URL, r.RemoteAddr)
				return
			}
			if subtle.ConstantTimeCompare(HmacSha256(text, password), mac) != 1 {
				http.NotFound(w, r)
				log.Infof("auth declined. method: %s, url: %s, remote: %s", r.Method, r.URL, r.RemoteAddr)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

// SetAuth ...
func SetAuth(r *http.Request, password string) {
	if r.Header == nil {
		r.Header = http.Header{}
	}
	auth := append([]byte("camo:"), HmacSha256("camo", password)...)
	r.Header.Set("Authorization", camoAuthTypeHMAC+" "+base64.StdEncoding.EncodeToString(auth))
}

// GetAuth ...
func GetAuth(r *http.Request) (text string, hmac []byte, ok bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return
	}
	const prefix = camoAuthTypeHMAC + " "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	i := bytes.IndexByte(c, ':')
	if i < 0 {
		return
	}
	return string(c[:i]), c[i+1:], true
}

// HmacSha256 ...
func HmacSha256(text string, password string) []byte {
	m := hmac.New(sha256.New, []byte(password))
	m.Write([]byte(text))
	return m.Sum(nil)
}
