package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/parametalol/hop/parser"
)

func TestExecuteRequest_BasicGET(t *testing.T) {
	// Create a test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method
		if r.Method != "GET" {
			t.Errorf("Expected GET request, got %s", r.Method)
		}

		// Send response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "success",
			"status":  "ok",
		})
	}))
	defer server.Close()

	// Create parsed request
	parsedReq := &parser.ParsedRequest{
		TargetURL: server.URL,
		Options:   map[string]string{},
	}

	// Execute request
	result := ExecuteRequest(parsedReq)

	// Verify no error
	if result.Error != "" {
		t.Errorf("Expected no error, got: %s", result.Error)
	}

	// Verify request metadata
	if result.OutgoingRequest.Method != "GET" {
		t.Errorf("Expected method GET, got %s", result.OutgoingRequest.Method)
	}
	if result.OutgoingRequest.URL != server.URL {
		t.Errorf("Expected URL %s, got %s", server.URL, result.OutgoingRequest.URL)
	}

	// Verify response metadata
	if result.Response.StatusCode != 200 {
		t.Errorf("Expected status code 200, got %d", result.Response.StatusCode)
	}
	if result.Response.Headers["Content-Type"] != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", result.Response.Headers["Content-Type"])
	}

	// Verify JSON body was parsed
	body, ok := result.Response.Body.(map[string]any)
	if !ok {
		t.Fatalf("Expected body to be parsed as map, got %T", result.Response.Body)
	}
	if body["message"] != "success" {
		t.Errorf("Expected message 'success', got %v", body["message"])
	}
}

func TestExecuteRequest_POST(t *testing.T) {
	receivedBody := ""

	// Create a test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		// Read and store body
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		receivedBody = string(buf)

		// Send response
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("created"))
	}))
	defer server.Close()

	// Create parsed request with POST method and data
	parsedReq := &parser.ParsedRequest{
		TargetURL: server.URL,
		Options: map[string]string{
			"method": "POST",
			"body":   `{"name":"test"}`,
		},
	}

	// Execute request
	result := ExecuteRequest(parsedReq)

	// Verify no error
	if result.Error != "" {
		t.Errorf("Expected no error, got: %s", result.Error)
	}

	// Verify request metadata
	if result.OutgoingRequest.Method != "POST" {
		t.Errorf("Expected method POST, got %s", result.OutgoingRequest.Method)
	}

	// Verify response
	if result.Response.StatusCode != 201 {
		t.Errorf("Expected status code 201, got %d", result.Response.StatusCode)
	}

	// Verify body was sent
	if receivedBody != `{"name":"test"}` {
		t.Errorf("Expected body %q, got %q", `{"name":"test"}`, receivedBody)
	}
}

func TestExecuteRequest_WithHeaders(t *testing.T) {
	receivedAuth := ""

	// Create a test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	// Create parsed request with header
	parsedReq := &parser.ParsedRequest{
		TargetURL: server.URL,
		Options: map[string]string{
			"H": "Authorization: Bearer token123",
		},
	}

	// Execute request
	result := ExecuteRequest(parsedReq)

	// Verify no error
	if result.Error != "" {
		t.Errorf("Expected no error, got: %s", result.Error)
	}

	// Verify header was sent
	if receivedAuth != "Bearer token123" {
		t.Errorf("Expected Authorization header %q, got %q", "Bearer token123", receivedAuth)
	}

	// Verify header was captured in request metadata
	if result.OutgoingRequest.Headers["Authorization"][0] != "Bearer token123" {
		t.Errorf("Expected Authorization in metadata, got %q", result.OutgoingRequest.Headers["Authorization"])
	}
}

func TestExecuteRequest_MethodAliases(t *testing.T) {
	tests := []struct {
		name           string
		optionKey      string
		optionValue    string
		expectedMethod string
	}{
		{
			name:           "method option",
			optionKey:      "method",
			optionValue:    "put",
			expectedMethod: "PUT",
		},
		{
			name:           "X option",
			optionKey:      "X",
			optionValue:    "delete",
			expectedMethod: "DELETE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receivedMethod := ""

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedMethod = r.Method
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			parsedReq := &parser.ParsedRequest{
				TargetURL: server.URL,
				Options: map[string]string{
					tt.optionKey: tt.optionValue,
				},
			}

			result := ExecuteRequest(parsedReq)

			if result.Error != "" {
				t.Errorf("Expected no error, got: %s", result.Error)
			}

			if receivedMethod != tt.expectedMethod {
				t.Errorf("Expected method %s, got %s", tt.expectedMethod, receivedMethod)
			}

			if result.OutgoingRequest.Method != tt.expectedMethod {
				t.Errorf("Expected request method %s, got %s", tt.expectedMethod, result.OutgoingRequest.Method)
			}
		})
	}
}

func TestExecuteRequest_JSONParsing(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		expectJSON  bool
	}{
		{
			name:        "JSON content type",
			contentType: "application/json",
			body:        `{"key":"value"}`,
			expectJSON:  true,
		},
		{
			name:        "JSON with charset",
			contentType: "application/json; charset=utf-8",
			body:        `{"key":"value"}`,
			expectJSON:  true,
		},
		{
			name:        "plain text",
			contentType: "text/plain",
			body:        `{"key":"value"}`,
			expectJSON:  false,
		},
		{
			name:        "invalid JSON with JSON content type",
			contentType: "application/json",
			body:        `not valid json`,
			expectJSON:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tt.contentType)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(tt.body))
			}))
			defer server.Close()

			parsedReq := &parser.ParsedRequest{
				TargetURL: server.URL,
				Options:   map[string]string{},
			}

			result := ExecuteRequest(parsedReq)

			if result.Error != "" {
				t.Errorf("Expected no error, got: %s", result.Error)
			}

			if tt.expectJSON {
				_, ok := result.Response.Body.(map[string]any)
				if !ok {
					t.Errorf("Expected body to be parsed as JSON map, got %T", result.Response.Body)
				}
			} else {
				_, ok := result.Response.Body.(string)
				if !ok {
					t.Errorf("Expected body to be string, got %T", result.Response.Body)
				}
			}
		})
	}
}

func TestExecuteRequest_InvalidURL(t *testing.T) {
	parsedReq := &parser.ParsedRequest{
		TargetURL: "http://invalid-url-that-does-not-exist-12345.com",
		Options:   map[string]string{},
	}

	result := ExecuteRequest(parsedReq)

	if result.Error == "" {
		t.Error("Expected error for invalid URL, got none")
	}
}

func TestExecuteRequest_ResponseHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "custom-value")
		w.Header().Set("X-Request-Id", "12345")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	parsedReq := &parser.ParsedRequest{
		TargetURL: server.URL,
		Options:   map[string]string{},
	}

	result := ExecuteRequest(parsedReq)

	if result.Error != "" {
		t.Errorf("Expected no error, got: %s", result.Error)
	}

	if result.Response.Headers["X-Custom-Header"] != "custom-value" {
		t.Errorf("Expected X-Custom-Header=custom-value, got %s", result.Response.Headers["X-Custom-Header"])
	}

	if result.Response.Headers["X-Request-Id"] != "12345" {
		t.Errorf("Expected X-Request-Id=12345, got %s", result.Response.Headers["X-Request-Id"])
	}
}

func TestExecuteRequest_CustomTimeout(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Delay for 2 seconds
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	// Test with 1 second timeout (should timeout)
	parsedReq := &parser.ParsedRequest{
		TargetURL: server.URL,
		Options: map[string]string{
			"timeout": "1",
		},
	}

	result := ExecuteRequest(parsedReq)

	// Should get a timeout error
	if result.Error == "" {
		t.Error("Expected timeout error, got none")
	}
	if !strings.Contains(result.Error, "timeout") && !strings.Contains(result.Error, "deadline") {
		t.Errorf("Expected timeout/deadline error, got: %s", result.Error)
	}
}

func TestExecuteRequest_CustomTimeoutSuccess(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Delay for 1 second
		time.Sleep(1 * time.Second)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	// Test with 3 second timeout (should succeed)
	parsedReq := &parser.ParsedRequest{
		TargetURL: server.URL,
		Options: map[string]string{
			"timeout": "3",
		},
	}

	result := ExecuteRequest(parsedReq)

	// Should succeed
	if result.Error != "" {
		t.Errorf("Expected no error, got: %s", result.Error)
	}
	if result.Response.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", result.Response.StatusCode)
	}
}

func TestExecuteRequest_InvalidTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	// Test with invalid timeout (should use default)
	parsedReq := &parser.ParsedRequest{
		TargetURL: server.URL,
		Options: map[string]string{
			"timeout": "invalid",
		},
	}

	result := ExecuteRequest(parsedReq)

	// Should succeed with default timeout
	if result.Error != "" {
		t.Errorf("Expected no error, got: %s", result.Error)
	}
}

func TestExecuteRequest_NoFollowRedirect(t *testing.T) {
	// Create a test server that redirects
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "/target")
			w.WriteHeader(http.StatusFound)
			w.Write([]byte("redirecting"))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("final destination"))
		}
	}))
	defer server.Close()

	// Test with follow-redirect disabled
	parsedReq := &parser.ParsedRequest{
		TargetURL: server.URL + "/redirect",
		Options: map[string]string{
			"follow-redirect": "false",
		},
	}

	result := ExecuteRequest(parsedReq)

	if result.Error != "" {
		t.Errorf("Expected no error, got: %s", result.Error)
	}

	// Should stop at the redirect response
	if result.Response.StatusCode != 302 {
		t.Errorf("Expected status code 302, got %d", result.Response.StatusCode)
	}

	// Should have Location header
	if result.Response.Headers["Location"] != "/target" {
		t.Errorf("Expected Location header '/target', got %s", result.Response.Headers["Location"])
	}
}

func TestExecuteRequest_FollowRedirect(t *testing.T) {
	// Create a test server that redirects
	finalPath := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		finalPath = r.URL.Path
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "/target")
			w.WriteHeader(http.StatusFound)
			w.Write([]byte("redirecting"))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("final destination"))
		}
	}))
	defer server.Close()

	// Test with default behavior (should follow redirects)
	parsedReq := &parser.ParsedRequest{
		TargetURL: server.URL + "/redirect",
		Options:   map[string]string{},
	}

	result := ExecuteRequest(parsedReq)

	if result.Error != "" {
		t.Errorf("Expected no error, got: %s", result.Error)
	}

	// Should follow redirect and get 200
	if result.Response.StatusCode != 200 {
		t.Errorf("Expected status code 200, got %d", result.Response.StatusCode)
	}

	// Should have reached the target path
	if finalPath != "/target" {
		t.Errorf("Expected final path '/target', got %s", finalPath)
	}
}

func TestProxyMetadata(t *testing.T) {
	// Test that ProxyMetadata can be properly set and serialized
	resp := &ProxyResponse{
		OutgoingRequest: &RequestMetadata{
			URL:    "http://example.com",
			Method: "GET",
		},
		Response: &ResponseMetadata{
			StatusCode: 200,
			Status:     "200 OK",
		},
		Proxy: &ProxyMetadata{
			Hostname:      "test-hostname",
			ListeningAddr: "localhost:8080",
			LocalTime:     "2025-01-15T12:00:00Z",
		},
	}

	// Verify proxy metadata is set
	if resp.Proxy == nil {
		t.Fatal("Expected proxy metadata to be set")
	}

	if resp.Proxy.Hostname != "test-hostname" {
		t.Errorf("Expected hostname 'test-hostname', got %s", resp.Proxy.Hostname)
	}

	if resp.Proxy.ListeningAddr != "localhost:8080" {
		t.Errorf("Expected listening addr 'localhost:8080', got %s", resp.Proxy.ListeningAddr)
	}

	if resp.Proxy.LocalTime != "2025-01-15T12:00:00Z" {
		t.Errorf("Expected local time '2025-01-15T12:00:00Z', got %s", resp.Proxy.LocalTime)
	}

	// Test JSON serialization
	jsonData, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal response to JSON: %v", err)
	}

	// Unmarshal and verify
	var unmarshaled ProxyResponse
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if unmarshaled.Proxy == nil {
		t.Fatal("Expected proxy metadata after unmarshal")
	}

	if unmarshaled.Proxy.Hostname != "test-hostname" {
		t.Errorf("After unmarshal: expected hostname 'test-hostname', got %s", unmarshaled.Proxy.Hostname)
	}
}

func TestDownstreamProxyMetadata(t *testing.T) {
	// Create a test server that simulates a downstream hop proxy
	// It returns a response with proxy metadata
	downstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Simulate a hop proxy response with proxy metadata
		downstreamResp := ProxyResponse{
			OutgoingRequest: &RequestMetadata{
				URL:    "http://final-destination.com",
				Method: "GET",
			},
			Response: &ResponseMetadata{
				StatusCode: 200,
				Status:     "200 OK",
				Body:       map[string]string{"result": "success"},
			},
			Proxy: &ProxyMetadata{
				Hostname:      "downstream-hop",
				ListeningAddr: "downstream:8080",
				LocalTime:     "2025-01-15T14:00:00Z",
			},
		}

		json.NewEncoder(w).Encode(downstreamResp)
	}))
	defer downstreamServer.Close()

	// Create parsed request to call the downstream server
	parsedReq := &parser.ParsedRequest{
		TargetURL: downstreamServer.URL,
		Options:   map[string]string{},
	}

	// Execute request (simulating the first hop calling downstream)
	result := ExecuteRequestWithContext(parsedReq, nil)

	// Manually set the proxy metadata for the first hop (normally done by server handler)
	result.Proxy = &ProxyMetadata{
		Hostname:      "upstream-hop",
		ListeningAddr: "upstream:8080",
		LocalTime:     "2025-01-15T13:00:00Z",
	}

	// Verify upstream proxy metadata
	if result.Proxy == nil {
		t.Fatal("Expected proxy metadata to be set")
	}
	if result.Proxy.Hostname != "upstream-hop" {
		t.Errorf("Expected upstream hostname 'upstream-hop', got %s", result.Proxy.Hostname)
	}

	// Verify that the response body contains the downstream hop's response
	// The downstream proxy metadata is naturally nested in the response body
	bodyMap, ok := result.Response.Body.(map[string]any)
	if !ok {
		t.Fatalf("Expected response body to be a map, got %T", result.Response.Body)
	}

	// Check for downstream proxy metadata
	proxyField, ok := bodyMap["proxy"].(map[string]any)
	if !ok {
		t.Fatalf("Expected proxy field in downstream response")
	}

	if proxyField["hostname"] != "downstream-hop" {
		t.Errorf("Expected downstream hostname 'downstream-hop', got %v", proxyField["hostname"])
	}

	if proxyField["listening_addr"] != "downstream:8080" {
		t.Errorf("Expected downstream listening addr 'downstream:8080', got %v", proxyField["listening_addr"])
	}

	// Test JSON serialization
	jsonData, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal result: %v", err)
	}

	var unmarshaled ProxyResponse
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	if unmarshaled.Proxy == nil {
		t.Fatal("Expected proxy metadata after unmarshal")
	}
	if unmarshaled.Proxy.Hostname != "upstream-hop" {
		t.Errorf("After unmarshal: expected upstream hostname 'upstream-hop', got %s", unmarshaled.Proxy.Hostname)
	}
}
