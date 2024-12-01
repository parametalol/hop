package tlstools

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"

	"github.com/parametalol/hop/pkg/common"
	"github.com/parametalol/hop/pkg/tools"
)

func PrintCert(r *tools.ArrLog, cert *x509.Certificate) {
	c, _ := json.Marshal((*common.Certificate)(cert))
	r.Append(string(c))
}

func AppendTLSInfo(r *tools.ArrLog, t *tls.ConnectionState, insecure bool) {
	if t == nil {
		r.Appendln("No TLS info.")
		return
	}
	r.Appendf("TLS version 0x%x, cipher 0x%x, protocol %s, server name %s",
		t.Version, t.CipherSuite, t.NegotiatedProtocol, t.ServerName,
	)

	if len(t.PeerCertificates) > 0 {
		r.Append("=== Peer certificates ===")
		for i, ps := range t.PeerCertificates {
			r.Appendf("%d.", i+1)
			PrintCert(r, ps)
		}
	}

	if len(t.VerifiedChains) == 0 {
		if insecure {
			r.Append("Verification disabled")
		} else {
			r.Appendf("Empty verified chain")
		}
	} else {
		r.Append("=== Verified chain ===")
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
