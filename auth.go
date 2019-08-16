package camo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
		user, mac, ok := GetAuth(r)
		if !ok {
			http.NotFound(w, r)
			log.Infof("no auth info. method: %s, url: %s, remote: %s", r.Method, r.URL, r.RemoteAddr)
			return
		}
		if HmacSha256(user, password) != mac {
			http.NotFound(w, r)
			log.Infof("auth declined. method: %s, url: %s, remote: %s", r.Method, r.URL, r.RemoteAddr)
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
	auth := "camo:" + HmacSha256("camo", password)
	r.Header.Set("Authorization", camoAuthTypeHMAC+" "+base64.StdEncoding.EncodeToString([]byte(auth)))
}

// GetAuth ...
func GetAuth(r *http.Request) (user, hmac string, ok bool) {
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
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
}

// HmacSha256 ...
func HmacSha256(text string, password string) string {
	m := hmac.New(sha256.New, []byte(password))
	m.Write([]byte(text))
	return hex.EncodeToString(m.Sum(nil))
}
