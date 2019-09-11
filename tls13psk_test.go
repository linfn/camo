package camo

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"
)

func TestTLSPSK(t *testing.T) {
	var (
		host             = "google.com"
		sessionTicketKey = [32]byte{1}
	)

	l, err := tls.Listen("tcp", "127.0.0.1:0", TLSPSKServerConfig(sessionTicketKey))
	if err != nil {
		t.Fatal(err)
	}

	srv := http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "Hello, client")
		}),
	}
	go srv.Serve(l)
	defer srv.Close()

	tlsCfg, err := TLSPSKClientConfig(host, sessionTicketKey)
	if err != nil {
		t.Fatal(err)
	}

	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}

	for i := 0; i < 2; i++ {
		resp, err := c.Get("https://" + l.Addr().String())
		if err != nil {
			t.Error(i, err)
		}
		resp.Body.Close()
	}

	tlsCfg.ClientSessionCache.Put(host, nil)

	resp, err := c.Get("https://" + l.Addr().String())
	if err != nil {
		t.Error(err)
	}
	resp.Body.Close()
}
