package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/parametalol/hop/client"
	"github.com/parametalol/hop/parser"
	"github.com/parametalol/hop/server"
	"github.com/parametalol/hop/tls_tools"
)

func main() {
	// Command line flags
	httpPort := flag.Int("http-port", 8080, "HTTP server port")
	httpsPort := flag.Int("https-port", 0, "HTTPS server port (0 to disable)")
	certFile := flag.String("cert", "", "TLS certificate file (required for HTTPS)")
	keyFile := flag.String("key", "", "TLS key file (required for HTTPS)")
	minTLSVersion := flag.String("min-tls", "1.2", "Minimum TLS version (1.0, 1.1, 1.2, 1.3)")
	maxTLSVersion := flag.String("max-tls", "1.3", "Maximum TLS version (1.0, 1.1, 1.2, 1.3)")
	certDNSNames := flag.String("cert-dns-names", "", "Comma-separated DNS names for self-signed certificate (e.g., 'example.com,*.example.com')")
	certIPAddrs := flag.String("cert-ip-addrs", "", "Comma-separated IP addresses for self-signed certificate (e.g., '192.168.1.1,10.0.0.1')")
	clientCertFile := flag.String("client-cert", "", "Client TLS certificate file for mTLS")
	clientKeyFile := flag.String("client-key", "", "Client TLS key file for mTLS")

	flag.Parse()

	// Check if a URL argument was provided
	args := flag.Args()
	if len(args) > 0 {
		// Execute request directly instead of starting server
		executeURLArgument(args[0])
		return
	}

	// Build config
	config := &server.Config{
		HTTPPort:  *httpPort,
		HTTPSPort: *httpsPort,
		TLS: server.TLSConfig{
			CertFile:    *certFile,
			KeyFile:     *keyFile,
			MinVersion:  tls_tools.ParseTLSVersion(*minTLSVersion),
			MaxVersion:  tls_tools.ParseTLSVersion(*maxTLSVersion),
			DNSNames:    *certDNSNames,
			IPAddresses: *certIPAddrs,
		},
	}

	if err := config.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	// Initialize TLS tools (generate keys for runtime certificate generation)
	if err := tls_tools.Init(); err != nil {
		log.Fatalf("Failed to initialize TLS tools: %v", err)
	}

	// Prepare client certificate for mTLS
	// Priority: --client-cert/--client-key > --cert/--key > runtime-generated
	if *clientCertFile != "" && *clientKeyFile != "" {
		tls_tools.ClientCertFile = *clientCertFile
		tls_tools.ClientKeyFile = *clientKeyFile
	} else if *certFile != "" && *keyFile != "" {
		tls_tools.ClientCertFile = *certFile
		tls_tools.ClientKeyFile = *keyFile
	}

	// Load client certificate from files if provided, otherwise use runtime-generated
	if tls_tools.ClientCertFile != "" && tls_tools.ClientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(tls_tools.ClientCertFile, tls_tools.ClientKeyFile)
		if err != nil {
			log.Printf("Warning: failed to load client certificate from %s: %v", tls_tools.ClientCertFile, err)
			log.Println("Using runtime-generated client certificate")
		} else {
			tls_tools.ClientCert = cert
		}
	}

	// Create HTTP handler
	mux := http.NewServeMux()
	mux.HandleFunc("/", server.ProxyHandler)

	// Channel to collect server errors
	errChan := make(chan error, 2)

	// Start HTTP server if enabled
	var httpServer *http.Server
	if config.HTTPPort > 0 {
		httpServer = &http.Server{
			Addr:    fmt.Sprintf(":%d", config.HTTPPort),
			Handler: mux,
		}

		go func() {
			log.Printf("Starting HTTP server on port %d", config.HTTPPort)
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errChan <- fmt.Errorf("HTTP server error: %w", err)
			}
		}()
	}

	// Start HTTPS server if enabled
	var httpsServer *http.Server
	if config.HTTPSPort > 0 {
		tlsConfig, err := config.GetTLSConfig()
		if err != nil {
			log.Fatalf("Failed to get TLS config: %v", err)
		}

		httpsServer = &http.Server{
			Addr:      fmt.Sprintf(":%d", config.HTTPSPort),
			Handler:   mux,
			TLSConfig: tlsConfig,
		}

		go func() {
			log.Printf("Starting HTTPS server on port %d", config.HTTPSPort)
			// Since certificates are already loaded in TLSConfig, pass empty strings
			// to ListenAndServeTLS to avoid double-loading
			if err := httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				errChan <- fmt.Errorf("HTTPS server error: %w", err)
			}
		}()
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Wait for shutdown signal or error
	select {
	case err := <-errChan:
		log.Fatalf("Server error: %v", err)
	case sig := <-sigChan:
		log.Printf("Received signal %v, shutting down...", sig)
	}

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if httpServer != nil {
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("HTTP server shutdown error: %v", err)
		} else {
			log.Println("HTTP server shut down gracefully")
		}
	}

	if httpsServer != nil {
		if err := httpsServer.Shutdown(ctx); err != nil {
			log.Printf("HTTPS server shutdown error: %v", err)
		} else {
			log.Println("HTTPS server shut down gracefully")
		}
	}

	log.Println("Server stopped")
}

func executeURLArgument(urlArg string) {
	// Parse the URL argument
	parsedReq, err := parser.ParsePath(urlArg)
	if err != nil {
		log.Fatalf("Failed to parse URL: %v", err)
	}

	if parsedReq == nil {
		log.Fatal("No URL provided")
	}

	// Execute the request
	result := client.ExecuteRequest(parsedReq)

	// Output the result as JSON
	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal response: %v", err)
	}

	fmt.Println(string(output))

	// Exit with error code if request failed
	if result.Error != "" {
		os.Exit(1)
	}
}
