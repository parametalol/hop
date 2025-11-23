package options

import (
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
	DropBody       optionName = "drop-body"
	Timeout        optionName = "timeout"
	Insecure       optionName = "insecure"
	ServerName     optionName = "tls-server-name"
	FollowRedirect optionName = "follow-redirect"
	ForwardHeaders optionName = "forward-headers"
	MTLS           optionName = "mtls"

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
	Headers:        {"H", "set request headers (format: 'Header: Value', newline-separated)"},
	Method:         {"X", "set HTTP method (GET, POST, PUT, DELETE, etc.)"},
	Body:           {"B", "set request body content"},
	BodyFile:       {"BF", "read request body from file"},
	DropBody:       {"DB", "drop the response body"},
	Timeout:        {"T", "set request timeout in seconds (default: 30)"},
	Insecure:       {"k", "skip TLS certificate verification"},
	ServerName:     {"SN", "set TLS server name for SNI"},
	FollowRedirect: {"L", "follow HTTP 3xx redirects (default: true)"},
	MTLS:           {"M", "use mutual TLS authentication"},
	ForwardHeaders: {"FH", "forward specific headers from incoming to outgoing request (comma-separated)"},

	// Server options:
	Code:          {"C", "return specific HTTP status code"},
	ServerHeaders: {"SH", "set response headers (format: 'Header: Value', newline-separated)"},
	Sleep:         {"S", "delay response by specified seconds"},
	Exit:          {"E", "terminate server process with exit code"},
	Panic:         {"P", "crash server process with panic message"},
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

// values yields the values of the option for long and short names, if set
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

func str(s string) string { return s }

func boolean(s string) bool { return s == "true" || s == "1" }

func getValue[T any](o Options, name optionName, def T, f func(string) T) T {
	for value := range o.values(name) {
		return f(value)
	}
	return def
}

// GetHTTPMethod determines the HTTP method from options
func (o Options) GetHTTPMethod() string {
	return getValue(o, Method, http.MethodGet, strings.ToUpper)
}

// GetRequestBody extracts the request body from options
// If body-file is specified, reads from the file; otherwise uses the body option
func (o Options) GetRequestBody() io.Reader {
	reader := getValue(o, BodyFile, nil, func(val string) io.Reader {
		file, err := os.Open(val)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to open body file %q: %v\n", val, err)
			return nil
		}
		return file
	})
	if reader == nil {
		// Fall back to body option
		reader = getValue(o, Body, nil, func(val string) io.Reader {
			return strings.NewReader(val)
		})
	}
	return reader
}

// GetHTTPStatus determines the HTTP method from options
func (o Options) GetHTTPStatus() int {
	return getValue(o, Code, http.StatusOK, func(val string) int {
		code, err := strconv.Atoi(val)
		if err != nil {
			return http.StatusNotAcceptable
		}
		return code
	})
}

// GetSleepDuration returns the sleep duration in seconds, or 0 if not set
func (o Options) GetSleepDuration() time.Duration {
	return getValue(o, Sleep, 0, func(val string) time.Duration {
		seconds, err := strconv.ParseFloat(val, 64)
		if err != nil || seconds < 0 {
			return 0
		}
		return time.Duration(seconds * float64(time.Second))
	})
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
		if val == "" || boolean(val) {
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
	if incomingHeaders == nil {
		return
	}
	headerSpec := getValue(o, ForwardHeaders, "", str)
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

// ApplyServerHeaders adds headers to the response from options
func (o Options) ApplyServerHeaders(h http.Header) {
	for headers := range o.values(ServerHeaders) {
		o.applyHeadersByKey(headers, h)
	}
}

func (o Options) IsFollowRedirect() bool {
	return getValue(o, FollowRedirect, true, boolean)
}

func (o Options) GetTimeout() time.Duration {
	return getValue(o, Timeout, 30*time.Second, func(val string) time.Duration {
		if timeoutSec, err := strconv.Atoi(val); err == nil && timeoutSec > 0 {
			return time.Duration(timeoutSec) * time.Second
		}
		return 30 * time.Second
	})
}

func (o Options) GetServerName() string {
	return getValue(o, ServerName, "", str)
}

func (o Options) IsInsecure() bool {
	return getValue(o, Insecure, false, boolean)
}

func (o Options) WithMTLS() bool {
	return getValue(o, MTLS, false, boolean)
}

func (o Options) IsDropBody() bool {
	return getValue(o, DropBody, false, boolean)
}

// PrintHelp outputs all supported options with their descriptions
func PrintHelp() string {
	result := &strings.Builder{}
	result.WriteString("Supported URL options:\n\n")
	result.WriteString("Client options (for making requests):\n")

	clientOptions := []optionName{
		Headers, Method, Body, BodyFile, Timeout, Insecure,
		ServerName, FollowRedirect, MTLS, ForwardHeaders,
	}

	for _, opt := range clientOptions {
		def := supportedOptions[opt]
		fmt.Fprintf(result, "  -%s, -%s\n      %s\n", opt, def.short, def.help)
	}

	result.WriteString("\nServer options (for response behavior):\n")

	serverOptions := []optionName{
		Code, ServerHeaders, Sleep, Exit, Panic,
	}

	for _, opt := range serverOptions {
		def := supportedOptions[opt]
		fmt.Fprintf(result, "  -%s, -%s\n      %s\n", opt, def.short, def.help)
	}

	return result.String()
}
