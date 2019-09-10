package camo

import (
	"crypto/rand"
	"crypto/rsa"
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
	key, err := rsa.GenerateKey(rand.Reader, 1024)
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

// TLSPSKSessionCache ...
func TLSPSKSessionCache(host string, sessionTicketKey [32]byte) (tls.ClientSessionCache, error) {
	cert, err := generateCert(host)
	if err != nil {
		return nil, err
	}

	srvTLSCfg := &tls.Config{
		SessionTicketKey: sessionTicketKey,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return cert, nil
		},
	}

	l, err := tls.Listen("tcp", "127.0.0.1:0", srvTLSCfg)
	if err != nil {
		return nil, err
	}

	srv := http.Server{
		Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	}
	go srv.Serve(l)
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
			},
		},
	}

	resp, err := c.Get("https://" + l.Addr().String())
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	return sessionCache, nil
}

// TLSPSKClientConfig ...
func TLSPSKClientConfig(host string, sessionTicketKey [32]byte) (*tls.Config, error) {
	sc, err := TLSPSKSessionCache(host, sessionTicketKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		ServerName:         host,
		ClientSessionCache: sc,
	}, nil
}

// TLSPSKServerConfig ...
func TLSPSKServerConfig(sessionTicketKey [32]byte) *tls.Config {
	return &tls.Config{
		SessionTicketKey: sessionTicketKey,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return nil, errors.New("(PSK) bad certificate")
		},
	}
}
