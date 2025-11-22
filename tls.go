package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// GenerateSelfSignedCert generates a self-signed certificate in memory
func GenerateSelfSignedCert(dnsNamesCSV, ipAddrsCSV string) (tls.Certificate, error) {
	// Generate private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Parse DNS names from comma-separated string
	dnsNames := []string{"localhost"}
	var commonName string = "localhost"

	if dnsNamesCSV != "" {
		for _, name := range strings.Split(dnsNamesCSV, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				dnsNames = append(dnsNames, name)
				// Use the first non-wildcard DNS name as CommonName
				if commonName == "localhost" && !strings.HasPrefix(name, "*") {
					commonName = name
				}
			}
		}
	}

	// Parse IP addresses from comma-separated string
	ipAddresses := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	if ipAddrsCSV != "" {
		for _, ipStr := range strings.Split(ipAddrsCSV, ",") {
			ipStr = strings.TrimSpace(ipStr)
			if ipStr != "" {
				ip := net.ParseIP(ipStr)
				if ip != nil {
					ipAddresses = append(ipAddresses, ip)
				}
			}
		}
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Auto-generated"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode private key
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to marshal private key: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Parse the certificate
	cert, err := tls.X509KeyPair(certPEM, privPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	return cert, nil
}
