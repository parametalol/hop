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

	ClientCert tls.Certificate

	privateKey      *ecdsa.PrivateKey
	privateKeyBytes []byte
)

func Init() error {
	var err error
	if privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}
	if privateKeyBytes, err = x509.MarshalECPrivateKey(privateKey); err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	if ClientCert, err = GenerateClientCert(); err != nil {
		return fmt.Errorf("failed to generate client certificate")
	}
	return nil
}

func newCertificateTemplate(cn string, usage x509.ExtKeyUsage) (*x509.Certificate, error) {
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"hop-proxy"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
	}, nil
}

// GenerateSelfSignedCert generates a self-signed certificate in memory
func GenerateSelfSignedCert(dnsNamesCSV, ipAddrsCSV string) (tls.Certificate, error) {
	if privateKey == nil || len(privateKeyBytes) == 0 {
		return tls.Certificate{}, errors.New("missing private key")
	}

	// Parse DNS names from comma-separated string
	dnsNames := []string{"localhost"}
	var commonName string = "localhost"

	if dnsNamesCSV != "" {
		for name := range strings.SplitSeq(dnsNamesCSV, ",") {
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
		for ipStr := range strings.SplitSeq(ipAddrsCSV, ",") {
			ipStr = strings.TrimSpace(ipStr)
			if ipStr != "" {
				ip := net.ParseIP(ipStr)
				if ip != nil {
					ipAddresses = append(ipAddresses, ip)
				}
			}
		}
	}

	template, err := newCertificateTemplate(commonName, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate server certificate template: %w", err)
	}

	template.DNSNames = dnsNames
	template.IPAddresses = ipAddresses

	return newCertificate(template)
}

func newCertificate(template *x509.Certificate) (tls.Certificate, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, template,
		&privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
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
	if privateKey == nil || len(privateKeyBytes) == 0 {
		return tls.Certificate{}, errors.New("missing private key")
	}
	template, err := newCertificateTemplate("hop-client", x509.ExtKeyUsageClientAuth)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate client certificate template: %w", err)
	}
	return newCertificate(template)
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

func ParseTLSVersion(version string) uint16 {
	switch version {
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12
	}
}
