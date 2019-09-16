package camo

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"time"
)

func generateCert(host string) (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24 * 365 * 10)

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &tlsCert, nil
}

func newPSKSession(host string, sessionTicketKey [32]byte) (*tls.ClientSessionState, error) {
	cert, err := generateCert(host)
	if err != nil {
		return nil, err
	}

	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		SessionTicketKey: sessionTicketKey,
		Certificates:     []tls.Certificate{*cert},
	})
	if err != nil {
		return nil, err
	}

	srv := http.Server{
		Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	}
	go func() { _ = srv.Serve(l) }()
	defer srv.Close()

	sessionCache := tls.NewLRUClientSessionCache(0)

	xcert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	certpool := x509.NewCertPool()
	certpool.AddCert(xcert)

	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         host,
				RootCAs:            certpool,
				ClientSessionCache: sessionCache,
				MinVersion:         tls.VersionTLS13,
			},
		},
	}

	resp, err := c.Get("https://" + l.Addr().String())
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	session, ok := sessionCache.Get(host)
	if !ok {
		return nil, errors.New("can not get session")
	}

	return session, nil
}

type pskSessionCache struct {
	host             string
	sessionTicketKey [32]byte
	cs               tls.ClientSessionCache
}

func (p *pskSessionCache) Get(sessionKey string) (session *tls.ClientSessionState, ok bool) {
	session, ok = p.cs.Get(sessionKey)
	if ok {
		return session, true
	}
	if sessionKey != p.host {
		return nil, false
	}
	session, err := newPSKSession(p.host, p.sessionTicketKey)
	if err != nil {
		return nil, false
	}
	p.Put(p.host, session)
	return session, true
}

func (p *pskSessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	p.cs.Put(sessionKey, cs)
}

// NewTLSPSKSessionCache ...
func NewTLSPSKSessionCache(host string, sessionTicketKey [32]byte) (tls.ClientSessionCache, error) {
	session, err := newPSKSession(host, sessionTicketKey)
	if err != nil {
		return nil, err
	}
	p := pskSessionCache{
		host:             host,
		sessionTicketKey: sessionTicketKey,
		cs:               tls.NewLRUClientSessionCache(0),
	}
	p.Put(host, session)
	return &p, nil
}

// NewSessionTicketKey ...
func NewSessionTicketKey(password string) (key [32]byte) {
	m := hmac.New(sha256.New, []byte(password))
	_, err := m.Write([]byte("camo-tls-psk"))
	if err != nil {
		panic(err)
	}
	m.Sum(key[:0])
	return
}
