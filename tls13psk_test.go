package camo

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/linfn/camo/internal/util"
)

func TestTLSPSK(t *testing.T) {
	var (
		host     = "google.com"
		password = "camotest"
	)

	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		SessionTicketKey: NewSessionTicketKey(password),
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return nil, errors.New("(PSK) bad certificate")
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "Hello, client")
		}),
	}
	go func() { _ = srv.Serve(l) }()
	defer srv.Close()

	cs, err := NewTLSPSKSessionCache(util.StripPort(host), NewSessionTicketKey(password))
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         util.StripPort(host),
				ClientSessionCache: cs,
			},
		},
	}

	for i := 0; i < 2; i++ {
		resp, err := c.Get("https://" + l.Addr().String())
		if err != nil {
			t.Error(i, err)
		} else {
			resp.Body.Close()
		}
	}

	cs.Put(util.StripPort(host), nil)

	resp, err := c.Get("https://" + l.Addr().String())
	if err != nil {
		t.Error(err)
	} else {
		resp.Body.Close()
	}
}
