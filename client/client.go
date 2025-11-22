package client

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/parametalol/hop/parser"
)

type RequestMetadata struct {
	URL        string            `json:"url"`
	Method     string            `json:"method"`
	Headers    map[string]string `json:"headers,omitempty"`
	Protocol   string            `json:"protocol"`
	BodyLength int               `json:"body_length"`
	Body       string            `json:"body,omitempty"`
}

type TLSInfo struct {
	Version            string `json:"version"`
	CipherSuite        string `json:"cipher_suite"`
	ServerName         string `json:"server_name"`
	NegotiatedProtocol string `json:"negotiated_protocol"`
}

type ProxyMetadata struct {
	Hostname      string `json:"hostname"`
	ListeningAddr string `json:"listening_addr,omitempty"`
	LocalTime     string `json:"local_time"`
}

type ResponseMetadata struct {
	StatusCode int               `json:"status_code"`
	Status     string            `json:"status"`
	Headers    map[string]string `json:"headers,omitempty"`
	Protocol   string            `json:"protocol"`
	TLS        *TLSInfo          `json:"tls,omitempty"`
	BodyLength int               `json:"body_length"`
	Body       any               `json:"body,omitempty"`
}

type ProxyResponse struct {
	Proxy           *ProxyMetadata    `json:"proxy,omitempty"`
	IncomingRequest *RequestMetadata  `json:"incoming_request,omitempty"`
	OutgoingRequest *RequestMetadata  `json:"outgoing_request,omitempty"`
	Response        *ResponseMetadata `json:"response,omitempty"`
	Error           string            `json:"error,omitempty"`
}

func ExecuteRequest(parsedReq *parser.ParsedRequest) *ProxyResponse {
	return ExecuteRequestWithContext(parsedReq, "", "", nil)
}

func ExecuteRequestWithClientCert(parsedReq *parser.ParsedRequest, clientCertFile, clientKeyFile string) *ProxyResponse {
	return ExecuteRequestWithContext(parsedReq, clientCertFile, clientKeyFile, nil)
}

func ExecuteRequestWithContext(parsedReq *parser.ParsedRequest, clientCertFile, clientKeyFile string, incomingHeaders http.Header) *ProxyResponse {
	resp := &ProxyResponse{
		OutgoingRequest: &RequestMetadata{
			URL:     parsedReq.TargetURL,
			Headers: make(map[string]string),
		},
	}

	// Build HTTP client with options and client cert applied
	client := parsedReq.Options.BuildHTTPClientWithCert(clientCertFile, clientKeyFile)

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

	// Capture request headers
	for k, v := range req.Header {
		if len(v) > 0 {
			resp.OutgoingRequest.Headers[k] = v[0]
		}
	}

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
		Headers:    make(map[string]string),
		Protocol:   httpResp.Proto,
		BodyLength: len(bodyBytes),
	}

	// Capture response headers
	for k, v := range httpResp.Header {
		if len(v) > 0 {
			resp.Response.Headers[k] = v[0]
		}
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

	// Capture TLS information if available
	if httpResp.TLS != nil {
		resp.Response.TLS = &TLSInfo{
			Version:            getTLSVersionName(httpResp.TLS.Version),
			CipherSuite:        tls.CipherSuiteName(httpResp.TLS.CipherSuite),
			ServerName:         httpResp.TLS.ServerName,
			NegotiatedProtocol: httpResp.TLS.NegotiatedProtocol,
		}
	}

	resp.OutgoingRequest.Protocol = httpResp.Request.Proto

	return resp
}

func getTLSVersionName(version uint16) string {
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
