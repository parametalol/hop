package tls_tools

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
	"os"
	"strings"
	"time"
)

// CertManager manages TLS certificates and keys
type CertManager struct {
	ClientCert tls.Certificate
	ServerCert tls.Certificate
	CACertPool *x509.CertPool

	privateKey      *ecdsa.PrivateKey
	privateKeyBytes []byte
}

// Config for initializing CertManager
type Config struct {
	ClientCertFile string
	ClientKeyFile  string
	ServerCertFile string
	ServerKeyFile  string
	CAFile         string
	DNSNames       string
	IPAddresses    string
}

// New creates a new CertManager
// If cert files are provided and exist, loads them; otherwise generates runtime certificates
func New(cfg *Config) (*CertManager, error) {
	cm := &CertManager{}

	// Try to load client certificate from files if provided
	clientCertLoaded := false
	if cfg != nil && cfg.ClientCertFile != "" && cfg.ClientKeyFile != "" {
		if err := cm.loadClientCertFromFile(cfg.ClientCertFile, cfg.ClientKeyFile); err == nil {
			clientCertLoaded = true
		}
	}

	// Try to load server certificate from files if provided
	serverCertLoaded := false
	if cfg != nil && cfg.ServerCertFile != "" && cfg.ServerKeyFile != "" {
		if err := cm.loadServerCertFromFile(cfg.ServerCertFile, cfg.ServerKeyFile); err == nil {
			serverCertLoaded = true
		}
	}

	// Only generate private key if neither client nor server cert was loaded
	if !clientCertLoaded && !serverCertLoaded {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}
		cm.privateKey = privateKey

		privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %w", err)
		}
		cm.privateKeyBytes = privateKeyBytes

		// Generate client certificate if not loaded
		if !clientCertLoaded {
			clientCert, err := cm.generateClientCert()
			if err != nil {
				return nil, fmt.Errorf("failed to generate client certificate: %w", err)
			}
			cm.ClientCert = clientCert
		}

		// Generate server certificate if not loaded and DNS/IP info provided
		if !serverCertLoaded && cfg != nil && (cfg.DNSNames != "" || cfg.IPAddresses != "") {
			if err := cm.generateServerCert(cfg.DNSNames, cfg.IPAddresses); err != nil {
				return nil, fmt.Errorf("failed to generate server certificate: %w", err)
			}
		}
	} else {
		// At least one cert was loaded, so we have a private key
		// If client cert wasn't loaded but server was, we can't generate client cert
		// (because we don't have access to the private key from the loaded server cert)
		// Similarly for server cert. This is fine - certs will be empty if not loaded.
	}

	// Load CA certificate if provided
	if cfg != nil && cfg.CAFile != "" {
		if err := cm.loadCAFromFile(cfg.CAFile); err != nil {
			return nil, fmt.Errorf("failed to load CA certificate: %w", err)
		}
	}

	return cm, nil
}

// loadClientCertFromFile loads a client certificate from files
func (cm *CertManager) loadClientCertFromFile(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load client certificate: %w", err)
	}
	cm.ClientCert = cert
	return nil
}

// loadServerCertFromFile loads a server certificate from files
func (cm *CertManager) loadServerCertFromFile(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load server certificate: %w", err)
	}
	cm.ServerCert = cert
	return nil
}

// generateServerCert generates a self-signed server certificate
func (cm *CertManager) generateServerCert(dnsNamesCSV, ipAddrsCSV string) error {
	cert, err := cm.generateSelfSignedCert(dnsNamesCSV, ipAddrsCSV)
	if err != nil {
		return err
	}
	cm.ServerCert = cert
	return nil
}

// loadCAFromFile loads a CA certificate from a PEM file
func (cm *CertManager) loadCAFromFile(caFile string) error {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("failed to read CA file: %w", err)
	}

	cm.CACertPool = x509.NewCertPool()
	if !cm.CACertPool.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("failed to parse CA certificate")
	}

	return nil
}

// GetServerTLSConfig creates a TLS config for the server
// If no server certificate is loaded, generates a default localhost certificate
func (cm *CertManager) GetServerTLSConfig(minVersion, maxVersion uint16) (*tls.Config, error) {
	// Check if server certificate is already loaded
	if len(cm.ServerCert.Certificate) == 0 {
		// No server certificate loaded, need to generate one
		fmt.Println("no TLS certificate provided, generating self-signed certificate for localhost")
		if err := cm.generateServerCert("", ""); err != nil {
			return nil, fmt.Errorf("failed to generate self-signed certificate: %w", err)
		}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cm.ServerCert},
		MinVersion:   minVersion,
		MaxVersion:   maxVersion,
	}

	return tlsConfig, nil
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

// generateSelfSignedCert generates a self-signed certificate in memory
func (cm *CertManager) generateSelfSignedCert(dnsNamesCSV, ipAddrsCSV string) (tls.Certificate, error) {
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

	return cm.newCertificate(template)
}

func (cm *CertManager) newCertificate(template *x509.Certificate) (tls.Certificate, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, template,
		&cm.privateKey.PublicKey, cm.privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: cm.privateKeyBytes,
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

// generateClientCert generates a client certificate for mTLS in memory
func (cm *CertManager) generateClientCert() (tls.Certificate, error) {
	template, err := newCertificateTemplate("hop-client", x509.ExtKeyUsageClientAuth)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate client certificate template: %w", err)
	}
	return cm.newCertificate(template)
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
