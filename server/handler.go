package server

import (
	"encoding/json"
	"encoding/pem"
	"io"
	logPkg "log"
	"net/http"
	"os"
	"time"

	"github.com/parametalol/hop/client"
	"github.com/parametalol/hop/parser"
	"github.com/parametalol/hop/tls_tools"
)

var log = logPkg.New(os.Stderr, "server: ", logPkg.LstdFlags)

func MakeProxyHandler(certManager *tls_tools.CertManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		proxyHandler(w, r, certManager)
	}
}

func proxyHandler(w http.ResponseWriter, r *http.Request, certManager *tls_tools.CertManager) {
	log.Printf("Received %s request to %s", r.Method, r.URL.Path)

	// Collect proxy metadata
	hostname, _ := os.Hostname()
	proxyMetadata := &client.ProxyMetadata{
		Hostname:      hostname,
		ListeningAddr: r.Host,
		LocalTime:     time.Now().Format(time.RFC3339),
	}

	// Parse the path
	parsedReq, err := parser.ParsePath(r.URL.Path)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid path: "+err.Error())
		return
	}

	// Initialize response with proxy and incoming request metadata
	proxyResp := &client.ProxyResponse{
		IncomingRequest: readIncomingRequest(r),
		Proxy:           proxyMetadata,
	}
	// Capture incoming request headers

	statusCode := proxyCall(parsedReq, proxyResp, w, r, certManager)

	// Send JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(proxyResp); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func readIncomingRequest(r *http.Request) *client.RequestMetadata {
	md := &client.RequestMetadata{
		URL:    r.URL.String(),
		Method: r.Method,
		CommonMetadata: client.CommonMetadata{
			Headers:  r.Header,
			Protocol: r.Proto,
			TLS:      client.ReadTLSInfo(r.TLS),
		},
	}

	// Capture incoming request body if present
	if r.Body != nil {
		bodyBytes, err := io.ReadAll(r.Body)
		if err == nil {
			md.Body = string(bodyBytes)
		}
		r.Body.Close()
	}
	return md
}

func proxyCall(parsedReq *parser.ParsedRequest, proxyResp *client.ProxyResponse, w http.ResponseWriter, r *http.Request, certManager *tls_tools.CertManager) int {
	if parsedReq == nil {
		return http.StatusOK
	}
	statusCode := parsedReq.Options.GetHTTPStatus()

	// Apply sleep if specified
	if sleepDuration := parsedReq.Options.GetSleepDuration(); sleepDuration > 0 {
		log.Printf("Sleeping for %v before processing request", sleepDuration)
		time.Sleep(sleepDuration)
	}

	// Check for panic option first
	if msg, shouldPanic := parsedReq.Options.GetPanicMessage(); shouldPanic {
		log.Printf("Panic triggered by request option: %s", msg)
		panic(msg)
	}

	// Check for exit option
	if exitCode, shouldExit := parsedReq.Options.GetExitCode(); shouldExit {
		log.Printf("Exit triggered by request option with code: %d", exitCode)
		// Send response before exiting
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"message":   "Server shutting down",
			"exit_code": exitCode,
		})
		// Give a brief moment for response to be sent
		time.Sleep(50 * time.Millisecond)
		os.Exit(exitCode)
	}

	log.Printf("Parsed target URL: %s, options: %v", parsedReq.TargetURL, parsedReq.Options)

	// Execute outgoing request if there's a target URL
	if parsedReq.TargetURL != "" {
		outgoingResp := client.ExecuteRequestWithContext(parsedReq, r.Header, certManager)
		if outgoingResp != nil {
			// Copy the outgoing request and response data
			proxyResp.OutgoingRequest = outgoingResp.OutgoingRequest
			proxyResp.Response = outgoingResp.Response
			proxyResp.Error = outgoingResp.Error
		}
		if proxyResp.Error != "" {
			statusCode = http.StatusBadGateway
		}
	}

	parsedReq.Options.ApplyServerHeaders(w.Header())
	return statusCode
}

func respondError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	resp := map[string]string{
		"error": message,
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Error encoding error response: %v", err)
	}
}

// ServerCertHandler returns the server certificate in PEM format
func ServerCertHandler(certManager *tls_tools.CertManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")

		// Return the stored server certificate
		if len(certManager.ServerCert.Certificate) == 0 {
			http.Error(w, "No server certificate available", http.StatusInternalServerError)
			return
		}

		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certManager.ServerCert.Certificate[0],
		})

		w.Write(certPEM)
	}
}

// ClientCertHandler returns the client certificate in PEM format
func ClientCertHandler(certManager *tls_tools.CertManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")

		// Return the pre-loaded client certificate
		if len(certManager.ClientCert.Certificate) == 0 {
			http.Error(w, "No client certificate available", http.StatusInternalServerError)
			return
		}

		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certManager.ClientCert.Certificate[0],
		})

		w.Write(certPEM)
	}
}
