package client

import "net/http"

type CommonMetadata struct {
	Headers  http.Header `json:"headers,omitempty"`
	Protocol string      `json:"protocol"`
	TLS      *TLSInfo    `json:"tls,omitempty"`
	Body     any         `json:"body,omitempty"`
}

type RequestMetadata struct {
	CommonMetadata
	URL    string `json:"url"`
	Method string `json:"method"`
	Host   string `json:"host,omitempty"`
}

type TLSInfo struct {
	Version             string   `json:"version"`
	CipherSuite         string   `json:"cipher_suite"`
	ServerName          string   `json:"server_name"`
	NegotiatedProtocol  string   `json:"negotiated_protocol"`
	PeerCertificates    int      `json:"peer_certificates,omitempty"`
	VerifiedChains      int      `json:"verified_chains,omitempty"`
	ClientAuth          bool     `json:"client_auth,omitempty"`
	PeerCertificatesSNI []string `json:"peer_certificates_sni,omitempty"`
}

type ProxyMetadata struct {
	Hostname      string `json:"hostname"`
	ListeningAddr string `json:"listening_addr,omitempty"`
	LocalTime     string `json:"local_time"`
}

type ResponseMetadata struct {
	CommonMetadata
	StatusCode int    `json:"status_code"`
	Status     string `json:"status"`
}

type ProxyResponse struct {
	Proxy           *ProxyMetadata    `json:"proxy,omitempty"`
	IncomingRequest *RequestMetadata  `json:"incoming_request,omitempty"`
	OutgoingRequest *RequestMetadata  `json:"outgoing_request,omitempty"`
	Response        *ResponseMetadata `json:"response,omitempty"`
	Error           string            `json:"error,omitempty"`
}
