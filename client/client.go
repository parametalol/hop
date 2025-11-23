package client

import (
	"bytes"
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
	// Build HTTP client with options applied
	client := BuildHTTPClient(parsedReq.Options, certManager)

	// Determine HTTP method from options
	method := parsedReq.Options.GetHTTPMethod()

	result := &ProxyResponse{
		OutgoingRequest: &RequestMetadata{
			URL:    parsedReq.TargetURL,
			Method: method,
		},
	}

	// Get request body from options
	reqBodyReader := parsedReq.Options.GetRequestBody()
	var reqBodyBuf *bytes.Buffer
	if reqBodyReader != nil {
		// If it's a closer, defer closing it
		if closer, ok := reqBodyReader.(io.Closer); ok {
			defer closer.Close()
		}

		// Use TeeReader to capture the body as it's sent
		reqBodyBuf = new(bytes.Buffer)
		reqBodyReader = io.TeeReader(reqBodyReader, reqBodyBuf)
	}

	// Create HTTP request
	req, err := http.NewRequest(method, parsedReq.TargetURL, reqBodyReader)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create request: %v", err)
		return result
	}

	parsedReq.Options.ApplyHeaders(req.Header)
	parsedReq.Options.ApplyForwardedHeaders(incomingHeaders, req.Header)

	result.OutgoingRequest.TLS = ReadTLSInfo(req.TLS)
	result.OutgoingRequest.Headers = req.Header
	result.OutgoingRequest.Protocol = req.Proto

	// Execute request
	httpResp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("request failed: %v", err)
		return result
	}
	defer httpResp.Body.Close()

	// After request is sent, capture the request body from the buffer
	if reqBodyBuf != nil {
		result.OutgoingRequest.Body = reqBodyBuf.String()
	}

	var respBodyBytes []byte
	if !parsedReq.Options.IsDropBody() {
		// Read response body
		respBodyBytes, err = io.ReadAll(httpResp.Body)
		if err != nil {
			result.Error = fmt.Sprintf("failed to read response body: %v", err)
			return result
		}
	}

	// Build response metadata
	result.Response = &ResponseMetadata{
		StatusCode: httpResp.StatusCode,
		Status:     httpResp.Status,
		CommonMetadata: CommonMetadata{
			Headers:  httpResp.Header,
			Protocol: httpResp.Proto,
			TLS:      ReadTLSInfo(httpResp.TLS),
		},
	}

	// Parse body as JSON if content-type is JSON
	contentType := httpResp.Header.Get("Content-Type")
	if len(respBodyBytes) > 0 {
		if strings.Contains(strings.ToLower(contentType), "application/json") {
			var parsedJSON any
			if err := json.Unmarshal(respBodyBytes, &parsedJSON); err == nil {
				result.Response.Body = parsedJSON
			} else {
				// If JSON parsing fails, fall back to string
				result.Response.Body = string(respBodyBytes)
			}
		} else {
			result.Response.Body = string(respBodyBytes)
		}
	}

	return result
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
