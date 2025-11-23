package tls_tools

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

var (
	ClientCertFile string
	ClientKeyFile  string

	PrivateKey *ecdsa.PrivateKey
)

func Init() error {
	var err error
	if PrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}
	return nil
}

// GenerateSelfSignedCert generates a self-signed certificate in memory
func GenerateSelfSignedCert(dnsNamesCSV, ipAddrsCSV string) (tls.Certificate, error) {
	if PrivateKey == nil {
		return tls.Certificate{}, errors.New("missing private key")
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
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template,
		&PrivateKey.PublicKey, PrivateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode private key
	privBytes, err := x509.MarshalECPrivateKey(PrivateKey)
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

// GenerateClientCert generates a client certificate for mTLS in memory
func GenerateClientCert() (tls.Certificate, error) {
	if PrivateKey == nil {
		return tls.Certificate{}, errors.New("missing private key")
	}

	// Create certificate template for client authentication
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "hop-client",
			Organization: []string{"Hop Auto-generated Client"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template,
		&PrivateKey.PublicKey, PrivateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create client certificate: %w", err)
	}

	// Encode private key
	privBytes, err := x509.MarshalECPrivateKey(PrivateKey)
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
		return tls.Certificate{}, fmt.Errorf("failed to parse generated client certificate: %w", err)
	}

	return cert, nil
}

func GetTLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}
