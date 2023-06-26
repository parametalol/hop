package tlstools

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/0x656b694d/hop/tools"
)

func GetCertPool(cacert string) (*x509.CertPool, error) {
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

func PrintCert(r *tools.ArrLog, cert *x509.Certificate) {
	r.Appendf("Issuer:       %s", cert.Issuer)
	r.Appendf("Is CA:        %v", cert.IsCA)
	r.Appendf("DNS Names:    %v", cert.DNSNames)
	r.Appendf("IP Addresses: %v", cert.IPAddresses)
	r.Appendf("URIs:         %v", cert.URIs)
	r.Append("Validity:")
	r.Appendf("  Not Before:   %v", cert.NotBefore)
	r.Appendf("  Not After:    %v", cert.NotAfter)
	r.Appendf("Signature Algorithm: %s", cert.SignatureAlgorithm)
}

func AppendTLSInfo(r *tools.ArrLog, t *tls.ConnectionState, insecure bool) {
	if t == nil {
		r.Appendln("No TLS info.")
		return
	}
	r.Appendf("TLS version 0x%x, cipher 0x%x, protocol %s, server name %s",
		t.Version, t.CipherSuite, t.NegotiatedProtocol, t.ServerName,
	)
	for _, ps := range t.PeerCertificates {
		PrintCert(r, ps)
	}

	if len(t.VerifiedChains) == 0 {
		if insecure {
			r.Append("Verification disabled")
		} else {
			r.Appendf("Empty verified chain")
		}
	} else {
		r.Append("Verified chain:")
		for _, chain := range t.VerifiedChains {
			for _, x := range chain {
				if x == nil {
					continue
				}
				r.Appendf("Verified issuer %v, subject %v", x.Issuer, x.Subject)
			}
		}
	}
}

func GenCA() (*x509.Certificate, []byte, *rsa.PrivateKey, error) {
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               pkix.Name{},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot generate CA private key: %w", err)
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot create CA certificate: %w", err)
	}
	caPEM, err := PEMEncode(caBytes, "CERTIFICATE")
	if err != nil {
		return nil, nil, nil, err
	}
	return ca, caPEM, caPrivKey, err
}

func PEMEncode(data []byte, dataType string) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := pem.Encode(buf, &pem.Block{Type: dataType, Bytes: data})
	if err != nil {
		return nil, fmt.Errorf("failed to PEM encode %s: %w", dataType, err)
	}
	return buf.Bytes(), nil
}

func PEMDecode(data []byte) []byte {
	block, _ := pem.Decode(data)
	return block.Bytes
}

func GenServerCert(names []string) (*x509.Certificate, *rsa.PrivateKey, error) {
	serverCert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		DNSNames:     names,
		Subject:      pkix.Name{},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
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
	return PEMEncode(certBytes, "CERTIFICATE")
}

func SelfSign(names []string) (*x509.Certificate, []byte, *rsa.PrivateKey, error) {
	ca, _, caPrivKey, err := GenCA()
	if err != nil {
		return nil, nil, nil, err
	}
	cert, pk, err := GenServerCert(names)
	if err != nil {
		return nil, nil, nil, err
	}
	signed, err := Sign(cert, ca, &pk.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return ca, signed, pk, err
}

func SignWith(names []string, cacertFile, cakeyFile string) (*tls.Certificate, error) {
	cert, pk, err := GenServerCert(names)
	if err != nil {
		return nil, err
	}
	pkPEM, err := PEMEncode(x509.MarshalPKCS1PrivateKey(pk), "RSA PRIVATE KEY")
	if err != nil {
		return nil, fmt.Errorf("cannot encode private key: %w", err)
	}
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
	signed, err := Sign(cert, cacert, &pk.PublicKey, rsaKey)
	if err != nil {
		return nil, err
	}
	serverCert, err := tls.X509KeyPair(signed, pkPEM)
	if err != nil {
		return nil, fmt.Errorf("cannot generate key pair: %w", err)
	}
	return &serverCert, nil
}

func GetSelfSigned(names []string) (*tls.Certificate, *x509.Certificate, error) {
	ca, cert, pk, err := SelfSign(names)
	if err != nil {
		return nil, nil, err
	}
	pkPEM, err := PEMEncode(x509.MarshalPKCS1PrivateKey(pk), "RSA PRIVATE KEY")
	if err != nil {
		return nil, nil, err
	}
	serverCert, err := tls.X509KeyPair(cert, pkPEM)
	if err != nil {
		return nil, nil, err
	}
	return &serverCert, ca, nil
}
