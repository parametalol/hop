package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

func getCertPool(cacert string) (*x509.CertPool, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to obtain the system certificates pool: %s", err)
	}
	if len(cacert) != 0 {
		data, err := os.ReadFile(cacert)
		if err != nil {
			return nil, fmt.Errorf("failed to load root certificate from %s: %s", cacert, err)
		}
		ok := roots.AppendCertsFromPEM(data)
		if !ok {
			return nil, fmt.Errorf("failed to parse root certificate from %s", cacert)
		}
	}
	return roots, nil
}

func appendTLSInfo(r *reqLog, t *tls.ConnectionState, prefix string) {
	if t == nil {
		return
	}
	r.appendf("%s: TLS version 0x%x, cipher 0x%x, protocol %s, server name %s",
		prefix,
		t.Version, t.CipherSuite, t.NegotiatedProtocol, t.ServerName)

	for _, chain := range t.VerifiedChains {
		for _, x := range chain {
			if x == nil {
				continue
			}
			r.appendf("%s: Verified issuer %v, subject %v", prefix, x.Issuer, x.Subject)
		}
	}

	if len(t.VerifiedChains) == 0 {
		r.appendf("%s: Empty verified chain", prefix)
	}
}
