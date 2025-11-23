package client

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/parametalol/hop/options"
	"github.com/parametalol/hop/parser"
	"github.com/parametalol/hop/tls_tools"
)

func ExecuteRequest(parsedReq *parser.ParsedRequest, certManager *tls_tools.CertManager) *ProxyResponse {
	return ExecuteRequestWithContext(parsedReq, nil, certManager)
}

func ExecuteRequestWithContext(parsedReq *parser.ParsedRequest, incomingHeaders http.Header, certManager *tls_tools.CertManager) *ProxyResponse {
	resp := &ProxyResponse{
		OutgoingRequest: &RequestMetadata{
			URL: parsedReq.TargetURL,
		},
	}

	// Build HTTP client with options applied
	client := BuildHTTPClient(parsedReq.Options, certManager)

	// Determine HTTP method from options
	method := parsedReq.Options.GetHTTPMethod()
	resp.OutgoingRequest.Method = method

	// Get request body from options
	bodyReader := parsedReq.Options.GetRequestBody()
	var bodyBytes []byte
	if bodyReader != nil {
		// If it's a closer, defer closing it
		if closer, ok := bodyReader.(io.Closer); ok {
			defer closer.Close()
		}

		var err error
		bodyBytes, err = io.ReadAll(bodyReader)
		if err != nil {
			resp.Error = fmt.Sprintf("failed to read request body: %v", err)
			return resp
		}
		resp.OutgoingRequest.BodyLength = len(bodyBytes)
		resp.OutgoingRequest.Body = string(bodyBytes)
		// Create a new reader from the bytes for the actual request
		bodyReader = strings.NewReader(string(bodyBytes))
	}

	// Create HTTP request
	req, err := http.NewRequest(method, parsedReq.TargetURL, bodyReader)
	if err != nil {
		resp.Error = fmt.Sprintf("failed to create request: %v", err)
		return resp
	}

	// Apply headers from options
	parsedReq.Options.ApplyHeaders(req.Header)

	// Apply forwarded headers from incoming request if available
	if incomingHeaders != nil {
		parsedReq.Options.ApplyForwardedHeaders(incomingHeaders, req.Header)
	}

	resp.OutgoingRequest.TLS = ReadTLSInfo(req.TLS)
	resp.OutgoingRequest.Headers = req.Header
	resp.OutgoingRequest.Protocol = req.Proto

	// Execute request
	httpResp, err := client.Do(req)
	if err != nil {
		resp.Error = fmt.Sprintf("request failed: %v", err)
		return resp
	}
	defer httpResp.Body.Close()

	// Read response body
	bodyBytes, err = io.ReadAll(httpResp.Body)
	if err != nil {
		resp.Error = fmt.Sprintf("failed to read response body: %v", err)
		return resp
	}

	// Build response metadata
	resp.Response = &ResponseMetadata{
		StatusCode: httpResp.StatusCode,
		Status:     httpResp.Status,
		Headers:    httpResp.Header,
		Protocol:   httpResp.Proto,
		BodyLength: len(bodyBytes),
		TLS:        ReadTLSInfo(httpResp.TLS),
	}

	// Parse body as JSON if content-type is JSON
	contentType := httpResp.Header.Get("Content-Type")
	if len(bodyBytes) > 0 {
		if strings.Contains(strings.ToLower(contentType), "application/json") {
			var parsedJSON any
			if err := json.Unmarshal(bodyBytes, &parsedJSON); err == nil {
				resp.Response.Body = parsedJSON
			} else {
				// If JSON parsing fails, fall back to string
				resp.Response.Body = string(bodyBytes)
			}
		} else {
			resp.Response.Body = string(bodyBytes)
		}
	}

	return resp
}

func ReadTLSInfo(s *tls.ConnectionState) *TLSInfo {
	if s == nil {
		return nil
	}
	info := &TLSInfo{
		Version:            tls_tools.GetTLSVersionName(s.Version),
		CipherSuite:        tls.CipherSuiteName(s.CipherSuite),
		ServerName:         s.ServerName,
		NegotiatedProtocol: s.NegotiatedProtocol,
	}

	// Check for mTLS (client certificate authentication)
	if len(s.PeerCertificates) > 0 {
		info.ClientAuth = true
		info.PeerCertificates = len(s.PeerCertificates)
		info.VerifiedChains = len(s.VerifiedChains)

		// Extract Subject Names from peer certificates
		var snis []string
		for _, cert := range s.PeerCertificates {
			if cert.Subject.CommonName != "" {
				snis = append(snis, cert.Subject.CommonName)
			}
		}
		if len(snis) > 0 {
			info.PeerCertificatesSNI = snis
		}
	}
	return info
}

// BuildHTTPClient creates an HTTP client with options applied
func BuildHTTPClient(o options.Options, certManager *tls_tools.CertManager) *http.Client {
	client := &http.Client{
		Timeout: o.GetTimeout(),
	}

	// Configure redirect policy - by default Go follows up to 10 redirects
	// If follow-redirect is explicitly set to false, don't follow redirects
	if !o.IsFollowRedirect() {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	if tlsConfig := buildTLSConfig(o, certManager); tlsConfig != nil {
		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	return client
}

// buildTLSConfig creates a TLS config from options
func buildTLSConfig(o options.Options, certManager *tls_tools.CertManager) *tls.Config {
	insecure := o.IsInsecure()
	useMTLS := o.WithMTLS()
	serverName := o.GetServerName()

	if serverName == "" && certManager.CACertPool == nil && !useMTLS && !insecure {
		return nil
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecure,
		ServerName:         serverName,
		RootCAs:            certManager.CACertPool,
	}

	if useMTLS {
		tlsConfig.Certificates = []tls.Certificate{certManager.ClientCert}
	}

	return tlsConfig
}
