package server

import (
	"fmt"
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
