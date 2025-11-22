package options

import (
	"crypto/tls"
	"fmt"
	"io"
	"iter"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type optionName string

type Options map[string]string

const (
	// Client options:
	Headers        optionName = "headers"
	Method         optionName = "method"
	Body           optionName = "body"
	BodyFile       optionName = "body-file"
	Timeout        optionName = "timeout"
	Insecure       optionName = "insecure"
	ServerName     optionName = "tls-server-name"
	FollowRedirect optionName = "follow-redirect"
	ForwardHeaders optionName = "forward-headers"

	// Server options:
	Code          optionName = "code"
	ServerHeaders optionName = "server-headers"
	Sleep         optionName = "sleep"
	Exit          optionName = "exit"
	Panic         optionName = "panic"
)

type optionDefinition struct {
	short string
	help  string
}

var supportedOptions = map[optionName]optionDefinition{
	// Client options:
	Headers:        {"H", "client headers"},
	Method:         {"X", "client call method"},
	Body:           {"b", "client call body"},
	BodyFile:       {"bf", "client call body from file"},
	Timeout:        {"T", "client call timeout"},
	Insecure:       {"k", "insecure client call"},
	ServerName:     {"SN", "TLS server name for client call"},
	FollowRedirect: {"L", "follow HTTP redirects"},
	ForwardHeaders: {"FH", "forward headers from incoming request to client call"},

	// Server options:
	Code:          {"C", "server return status code"},
	ServerHeaders: {"SH", "server return headers"},
	Sleep:         {"s", "server sleep duration in seconds before processing"},
	Exit:          {"E", "exit server process with given code"},
	Panic:         {"P", "panic server process with given message"},
}

// Check verifies if opt is a known option
func Check(opt string) bool {
	if _, ok := supportedOptions[optionName(opt)]; ok {
		return true
	}
	for _, def := range supportedOptions {
		if def.short == opt {
			return true
		}
	}
	return false
}

func (o Options) values(optName optionName) iter.Seq[string] {
	return func(yield func(string) bool) {
		def, ok := supportedOptions[optName]
		if !ok {
			return
		}
		if val, ok := o[string(optName)]; ok && !yield(val) {
			return
		}
		if val, ok := o[def.short]; ok {
			yield(val)
		}
	}
}

// GetHTTPMethod determines the HTTP method from options
func (o Options) GetHTTPMethod() string {
	for method := range o.values(Method) {
		return strings.ToUpper(method)
	}
	return "GET"
}

// GetRequestBody extracts the request body from options
// If body-file is specified, reads from the file; otherwise uses the body option
func (o Options) GetRequestBody() io.Reader {
	// Check for body-file option first (takes precedence)
	for filePath := range o.values(BodyFile) {
		file, err := os.Open(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to open body file %q: %v\n", filePath, err)
			return nil
		}
		return file
	}

	// Fall back to body option
	for body := range o.values(Body) {
		return strings.NewReader(body)
	}
	return nil
}

// GetHTTPStatus determines the HTTP method from options
func (o Options) GetHTTPStatus() int {
	// Check for method options in order of precedence
	for val := range o.values(Code) {
		code, err := strconv.Atoi(val)
		if err != nil {
			return http.StatusNotAcceptable
		}
		return code
	}
	return http.StatusOK
}

// GetSleepDuration returns the sleep duration in seconds, or 0 if not set
func (o Options) GetSleepDuration() time.Duration {
	for val := range o.values(Sleep) {
		seconds, err := strconv.ParseFloat(val, 64)
		if err != nil || seconds < 0 {
			return 0
		}
		return time.Duration(seconds * float64(time.Second))
	}
	return 0
}

// GetExitCode returns the exit code if the exit option is set, and a bool indicating if it was set
func (o Options) GetExitCode() (int, bool) {
	for val := range o.values(Exit) {
		code, err := strconv.Atoi(val)
		if err != nil {
			return 1, true // Default to exit code 1 if invalid
		}
		return code, true
	}
	return 0, false
}

// GetPanicMessage returns the panic message if the panic option is set, and a bool indicating if it was set
func (o Options) GetPanicMessage() (string, bool) {
	for val := range o.values(Panic) {
		if val == "" || val == "true" || val == "1" {
			return "server panic triggered by request option", true
		}
		return val, true
	}
	return "", false
}

func (o Options) applyHeadersByKey(headers string, h http.Header) {
	for header := range strings.SplitSeq(headers, string(rune(0x0A))) {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			h.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
}

// ApplyHeaders adds headers to the request from options
func (o Options) ApplyHeaders(h http.Header) {
	for headers := range o.values(Headers) {
		o.applyHeadersByKey(headers, h)
	}
}

// ApplyForwardedHeaders forwards specified headers from the incoming request to the outgoing request
func (o Options) ApplyForwardedHeaders(incomingHeaders, outgoingHeaders http.Header) {
	for headerSpec := range o.values(ForwardHeaders) {
		// Support comma-separated list of headers to forward
		for headerName := range strings.SplitSeq(headerSpec, ",") {
			headerName = strings.TrimSpace(headerName)
			if headerName == "" {
				continue
			}
			// Forward the header if it exists in the incoming request
			if values := incomingHeaders.Values(headerName); len(values) > 0 {
				for _, v := range values {
					outgoingHeaders.Add(headerName, v)
				}
			}
		}
	}
}

// ApplyServerHeaders adds headers to the response from options
func (o Options) ApplyServerHeaders(h http.Header) {
	for headers := range o.values(ServerHeaders) {
		o.applyHeadersByKey(headers, h)
	}
}

// BuildHTTPClientWithCert creates an HTTP client with options and client cert applied
func (o Options) BuildHTTPClientWithCert(clientCertFile, clientKeyFile string) *http.Client {
	// Get timeout from options, default to 30 seconds
	timeout := 30 * time.Second
	for timeoutStr := range o.values(Timeout) {
		if timeoutSec, err := strconv.Atoi(timeoutStr); err == nil && timeoutSec > 0 {
			timeout = time.Duration(timeoutSec) * time.Second
		}
	}

	client := &http.Client{
		Timeout: timeout,
	}

	// Configure redirect policy - by default Go follows up to 10 redirects
	// If follow-redirect is explicitly set to false, don't follow redirects
	followRedirect := true
	for val := range o.values(FollowRedirect) {
		followRedirect = val == "true" || val == "1"
	}
	if !followRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// Build TLS config if needed
	tlsConfig := o.buildTLSConfig(clientCertFile, clientKeyFile)
	if tlsConfig != nil {
		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	return client
}

// buildTLSConfig creates a TLS config from options and client certificate files
func (o Options) buildTLSConfig(clientCertFile, clientKeyFile string) *tls.Config {
	var tlsConfig *tls.Config

	// Check for insecure option
	insecure := false
	for val := range o.values(Insecure) {
		insecure = val == "true" || val == "1"
	}

	// Check if client certificate files are provided
	hasCert := clientCertFile != "" && clientKeyFile != ""

	// Check for TLS server name override
	var serverName string
	for serverName = range o.values(ServerName) {
	}

	// If we need TLS config, create it
	if insecure || hasCert || serverName != "" {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: insecure,
		}
		tlsConfig.ServerName = serverName

		// Load client certificate if provided
		if hasCert {
			cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
			if err != nil {
				// Log error but don't fail - just skip mTLS
				fmt.Fprintf(os.Stderr, "Warning: failed to load client certificate: %v\n", err)
			} else {
				tlsConfig.Certificates = []tls.Certificate{cert}
			}
		}
	}

	return tlsConfig
}
