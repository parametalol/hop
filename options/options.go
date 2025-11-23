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

type option int

type optionName string

type Options map[string]string

const (
	// Client options:
	clientOptHeaders        option = iota
	clientOptMethod         option = iota
	clientOptBody           option = iota
	clientOptBodyFile       option = iota
	clientOptDropBody       option = iota
	clientOptTimeout        option = iota
	clientOptInsecure       option = iota
	clientOptServerName     option = iota
	clientOptFollowRedirect option = iota
	clientOptForwardHeaders option = iota
	clientOptMTLS           option = iota

	// Server options:
	serverOptCode    option = iota
	serverOptHeaders option = iota
	serverOptSleep   option = iota
	serverOptExit    option = iota
	serverOptPanic   option = iota
)

type optionDefinition struct {
	long  optionName
	short optionName
	help  string
}

type optionEntry struct {
	id  option
	def optionDefinition
}

type optionGroup struct {
	name    string
	options []optionEntry
}

var optionGroups = []optionGroup{
	{
		name: "Client Options",
		options: []optionEntry{
			{clientOptHeaders, optionDefinition{"headers", "H", "set request headers (format: 'Header: Value', newline-separated)"}},
			{clientOptMethod, optionDefinition{"method", "X", "set HTTP method (GET, POST, PUT, DELETE, etc.)"}},
			{clientOptBody, optionDefinition{"body", "B", "set request body content"}},
			{clientOptBodyFile, optionDefinition{"body-file", "BF", "read request body from file"}},
			{clientOptDropBody, optionDefinition{"drop-body", "DB", "drop the response body"}},
			{clientOptTimeout, optionDefinition{"timeout", "T", "set request timeout in seconds (default: 30)"}},
			{clientOptInsecure, optionDefinition{"insecure", "k", "skip TLS certificate verification"}},
			{clientOptServerName, optionDefinition{"tls-server-name", "SN", "set TLS server name for SNI"}},
			{clientOptFollowRedirect, optionDefinition{"follow-redirect", "L", "follow HTTP 3xx redirects (default: true)"}},
			{clientOptForwardHeaders, optionDefinition{"forward-headers", "M", "use mutual TLS authentication"}},
			{clientOptMTLS, optionDefinition{"mtls", "FH", "forward specific headers from incoming to outgoing request (comma-separated)"}},
		},
	},
	{
		name: "Server Options",
		options: []optionEntry{
			{serverOptCode, optionDefinition{"code", "C", "return specific HTTP status code"}},
			{serverOptHeaders, optionDefinition{"server-headers", "SH", "set response headers (format: 'Header: Value', newline-separated)"}},
			{serverOptSleep, optionDefinition{"sleep", "S", "delay response by specified seconds"}},
			{serverOptExit, optionDefinition{"exit", "E", "terminate server process with exit code"}},
			{serverOptPanic, optionDefinition{"panic", "P", "crash server process with panic message"}},
		},
	},
}

// Build lookup map for validation from the structured groups
var supportedOptionsByID, supportedOptions = buildOptionsMaps()

func buildOptionsMaps() (map[option]optionDefinition, map[optionName]optionDefinition) {
	m := make(map[optionName]optionDefinition)
	mID := make(map[option]optionDefinition)
	for _, group := range optionGroups {
		for _, opt := range group.options {
			mID[opt.id] = opt.def
			m[opt.def.long] = opt.def
			m[opt.def.short] = opt.def
		}
	}
	return mID, m
}

// Check verifies if opt is a known option
func Check(opt string) bool {
	_, ok := supportedOptions[optionName(opt)]
	return ok
}

// values yields the values of the option for long and short names, if set
func (o Options) values(id option) iter.Seq[string] {
	return func(yield func(string) bool) {
		def, ok := supportedOptionsByID[id]
		if !ok {
			return
		}
		if val, ok := o[string(def.long)]; ok && !yield(val) {
			return
		}
		if val, ok := o[string(def.short)]; ok {
			yield(val)
		}
	}
}

func str(s string) string { return s }

func boolean(s string) bool { return s == "true" || s == "1" }

func getValue[T any](o Options, id option, def T, f func(string) T) T {
	for value := range o.values(id) {
		return f(value)
	}
	return def
}

// GetHTTPMethod determines the HTTP method from options
func (o Options) GetHTTPMethod() string {
	return getValue(o, clientOptMethod, http.MethodGet, strings.ToUpper)
}

// GetRequestBody extracts the request body from options
// If body-file is specified, reads from the file; otherwise uses the body option
func (o Options) GetRequestBody() io.Reader {
	reader := getValue(o, clientOptBodyFile, nil, func(val string) io.Reader {
		file, err := os.Open(val)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to open body file %q: %v\n", val, err)
			return nil
		}
		return file
	})
	if reader == nil {
		// Fall back to body option
		reader = getValue(o, clientOptBody, nil, func(val string) io.Reader {
			return strings.NewReader(val)
		})
	}
	return reader
}

// GetHTTPStatus determines the HTTP method from options
func (o Options) GetHTTPStatus() int {
	return getValue(o, serverOptCode, http.StatusOK, func(val string) int {
		code, err := strconv.Atoi(val)
		if err != nil {
			return http.StatusNotAcceptable
		}
		return code
	})
}

// GetSleepDuration returns the sleep duration in seconds, or 0 if not set
func (o Options) GetSleepDuration() time.Duration {
	return getValue(o, serverOptSleep, 0, func(val string) time.Duration {
		seconds, err := strconv.ParseFloat(val, 64)
		if err != nil || seconds < 0 {
			return 0
		}
		return time.Duration(seconds * float64(time.Second))
	})
}

// GetExitCode returns the exit code if the exit option is set, and a bool indicating if it was set
func (o Options) GetExitCode() (int, bool) {
	for val := range o.values(serverOptExit) {
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
	for val := range o.values(serverOptPanic) {
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
	for headers := range o.values(clientOptHeaders) {
		o.applyHeadersByKey(headers, h)
	}
}

// ApplyForwardedHeaders forwards specified headers from the incoming request to the outgoing request
func (o Options) ApplyForwardedHeaders(incomingHeaders, outgoingHeaders http.Header) {
	if incomingHeaders == nil {
		return
	}
	headerSpec := getValue(o, clientOptForwardHeaders, "", str)
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
	for headers := range o.values(serverOptHeaders) {
		o.applyHeadersByKey(headers, h)
	}
}

func (o Options) IsFollowRedirect() bool {
	return getValue(o, clientOptFollowRedirect, true, boolean)
}

func (o Options) GetTimeout() time.Duration {
	return getValue(o, clientOptTimeout, 30*time.Second, func(val string) time.Duration {
		if timeoutSec, err := strconv.Atoi(val); err == nil && timeoutSec > 0 {
			return time.Duration(timeoutSec) * time.Second
		}
		return 30 * time.Second
	})
}

func (o Options) GetServerName() string {
	return getValue(o, clientOptServerName, "", str)
}

func (o Options) IsInsecure() bool {
	return getValue(o, clientOptInsecure, false, boolean)
}

func (o Options) WithMTLS() bool {
	return getValue(o, clientOptMTLS, false, boolean)
}

func (o Options) IsDropBody() bool {
	return getValue(o, clientOptDropBody, false, boolean)
}

// PrintHelp outputs all supported options with their descriptions
func PrintHelp() string {
	result := &strings.Builder{}

	for i, group := range optionGroups {
		if i > 0 {
			result.WriteString("\n")
		}
		fmt.Fprintf(result, "%s:\n", group.name)
		for _, opt := range group.options {
			fmt.Fprintf(result, "  -%s, -%s\n      %s\n", opt.def.long, opt.def.short, opt.def.help)
		}
	}

	return result.String()
}
