package tlstools

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	ca   *x509.Certificate
	capk *rsa.PrivateKey
	pool *x509.CertPool
)

//go:embed ca.crt
var caCRTfile string

//go:embed ca.key
var caPKfile string

func Init(builtin_ca bool) {
	var err error
	if builtin_ca {
		capk, _ = x509.ParsePKCS1PrivateKey(PEMDecode([]byte(caPKfile)))
		ca, _ = x509.ParseCertificate(PEMDecode([]byte(caCRTfile)))
	} else {
		ca, capk, err = genCA()
		if err != nil {
			log.Panic(err)
		}
	}
	pool, err = x509.SystemCertPool()
	if err != nil {
		log.Panicf("failed to obtain the system certificates pool: %s", err)
	}
	pool.AddCert(ca)
}

func GetCertPool(cacert string) (*x509.CertPool, error) {
	if cacert == "" {
		return pool, nil
	}
	data, err := os.ReadFile(cacert)
	if err != nil {
		return nil, fmt.Errorf("failed to load root certificate from %s: %s", cacert, err)
	}
	ok := pool.AppendCertsFromPEM(data)
	if !ok {
		return nil, fmt.Errorf("failed to parse root certificate from %s", cacert)
	}
	return pool, nil
}

func genCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	name := pkix.Name{
		CommonName: "Hop dynamic CA",
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               name,
		Issuer:                name,
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate CA private key: %w", err)
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create CA certificate: %w", err)
	}
	cacert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, nil, err
	}
	log.Info("CA certificate:")
	log.Info(string(PEMEncode(caBytes, "CERTIFICATE")))
	log.Info(string(PEMEncode(x509.MarshalPKCS1PrivateKey(caPrivKey), "RSA PRIVATE KEY")))

	return cacert, caPrivKey, err
}

func PEMEncode(data []byte, dataType string) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: dataType, Bytes: data})
}

func PEMDecode(data []byte) []byte {
	block, _ := pem.Decode(data)
	return block.Bytes
}

func GenCert(names []string, cn string) (*x509.Certificate, *rsa.PrivateKey, error) {
	now := time.Now()
	serverCert := &x509.Certificate{
		SerialNumber: big.NewInt(2023),
		DNSNames:     names,
		Issuer:       ca.Issuer,
		Subject:      pkix.Name{CommonName: cn},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    now,
		NotAfter:     now.AddDate(10, 0, 0),
		IsCA:         true,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate private key: %w", err)
	}
	return serverCert, certPrivKey, nil
}

func Sign(serviceCert, ca *x509.Certificate, serviceCertPubKey *rsa.PublicKey, caPrivKey *rsa.PrivateKey) ([]byte, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, serviceCert, ca, serviceCertPubKey, caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("cannot sign server certificate: %w", err)
	}
	return PEMEncode(certBytes, "CERTIFICATE"), nil
}

func SelfSign(names []string, cn string) ([]byte, *rsa.PrivateKey, error) {
	cert, pk, err := GenCert(names, cn)
	if err != nil {
		return nil, nil, err
	}
	signedPEM, err := Sign(cert, ca, &pk.PublicKey, capk)
	if err != nil {
		return nil, nil, err
	}
	return signedPEM, pk, err
}

func SignWith(names []string, cn, cacertFile, cakeyFile string) (*tls.Certificate, error) {
	if cacertFile == "" || cakeyFile == "" {
		return GetSelfSigned(names, cn)
	}
	cert, pk, err := GenCert(names, cn)
	if err != nil {
		return nil, err
	}
	pkPEM := PEMEncode(x509.MarshalPKCS1PrivateKey(pk), "RSA PRIVATE KEY")
	cacertBytes, err := os.ReadFile(cacertFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read cacert file: %w", err)
	}
	cakeyBytes, err := os.ReadFile(cakeyFile)
	if err != nil {
		return nil, err
	}

	cacert, err := x509.ParseCertificate(PEMDecode(cacertBytes))
	if err != nil {
		return nil, err
	}
	cakey, err := x509.ParsePKCS8PrivateKey(PEMDecode(cakeyBytes))
	if err != nil {
		return nil, fmt.Errorf("cannot parse CA private key: %w", err)
	}
	rsaKey, ok := cakey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key in %s", cakeyFile)
	}
	signedPEM, err := Sign(cert, cacert, &pk.PublicKey, rsaKey)
	if err != nil {
		return nil, err
	}
	serverCert, err := tls.X509KeyPair(signedPEM, pkPEM)
	if err != nil {
		return nil, fmt.Errorf("cannot generate key pair: %w", err)
	}
	return &serverCert, nil
}

func GetSelfSigned(names []string, cn string) (*tls.Certificate, error) {
	certPEM, pk, err := SelfSign(names, cn)
	if err != nil {
		return nil, err
	}
	pkPEM := PEMEncode(x509.MarshalPKCS1PrivateKey(pk), "RSA PRIVATE KEY")
	serverCert, err := tls.X509KeyPair(certPEM, pkPEM)
	if err != nil {
		return nil, err
	}
	return &serverCert, nil
}
