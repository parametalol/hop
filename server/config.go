package server

import (
	"crypto/tls"
	"fmt"
	"log"

	"github.com/parametalol/hop/tls_tools"
)

type Config struct {
	HTTPPort  int
	HTTPSPort int
	TLS       TLSConfig
}

type TLSConfig struct {
	CertFile    string
	KeyFile     string
	MinVersion  uint16
	MaxVersion  uint16
	DNSNames    string // Comma-separated DNS names for self-signed cert
	IPAddresses string // Comma-separated IP addresses for self-signed cert
}

func (c *Config) Validate() error {
	if c.HTTPPort <= 0 && c.HTTPSPort <= 0 {
		return fmt.Errorf("at least one of HTTPPort or HTTPSPort must be specified")
	}
	return nil
}

func (c *Config) GetTLSConfig() (*tls.Config, error) {
	var cert tls.Certificate
	var err error

	// If cert/key files are provided, load them
	if c.TLS.CertFile != "" && c.TLS.KeyFile != "" {
		cert, err = tls.LoadX509KeyPair(c.TLS.CertFile, c.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		log.Println("Using provided TLS certificate and key files")
	} else {
		// Generate self-signed certificate at runtime
		log.Println("No TLS certificate provided, generating self-signed certificate")
		cert, err = tls_tools.GenerateSelfSignedCert(c.TLS.DNSNames, c.TLS.IPAddresses)
		if err != nil {
			return nil, fmt.Errorf("failed to generate self-signed certificate: %w", err)
		}
		if c.TLS.DNSNames != "" || c.TLS.IPAddresses != "" {
			log.Printf("Generated self-signed certificate (DNS names: %s, IP addresses: %s)",
				c.TLS.DNSNames, c.TLS.IPAddresses)
		} else {
			log.Println("Generated self-signed certificate for localhost")
		}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12, // Default minimum
		MaxVersion:   tls.VersionTLS13, // Default maximum
	}

	if c.TLS.MinVersion != 0 {
		tlsConfig.MinVersion = c.TLS.MinVersion
	}
	if c.TLS.MaxVersion != 0 {
		tlsConfig.MaxVersion = c.TLS.MaxVersion
	}

	return tlsConfig, nil
}
