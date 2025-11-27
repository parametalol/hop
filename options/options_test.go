package options

import (
	"net/http"
	"slices"
	"testing"
	"time"
)

func TestOptionsValues(t *testing.T) {
	opts := make(Options)
	opts["method"] = "GET"
	opts["X"] = "POST"
	methods := slices.Collect(opts.values(clientOptMethod))
	if len(methods) != 2 || methods[0] != "GET" || methods[1] != "POST" {
		t.Errorf("options values returned %v, want: [GET, POST]", methods)
	}
}

func TestGetSleepDuration(t *testing.T) {
	tests := []struct {
		name     string
		options  Options
		expected time.Duration
	}{
		{
			name:     "integer seconds",
			options:  Options{"sleep": "2"},
			expected: 2 * time.Second,
		},
		{
			name:     "fractional seconds",
			options:  Options{"sleep": "1.5"},
			expected: 1500 * time.Millisecond,
		},
		{
			name:     "short form",
			options:  Options{"S": "3"},
			expected: 3 * time.Second,
		},
		{
			name:     "zero value",
			options:  Options{"sleep": "0"},
			expected: 0,
		},
		{
			name:     "no sleep option",
			options:  Options{},
			expected: 0,
		},
		{
			name:     "invalid value",
			options:  Options{"sleep": "invalid"},
			expected: 0,
		},
		{
			name:     "negative value",
			options:  Options{"sleep": "-1"},
			expected: 0,
		},
		{
			name:     "very small fractional",
			options:  Options{"sleep": "0.1"},
			expected: 100 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.options.GetSleepDuration()
			if result != tt.expected {
				t.Errorf("GetSleepDuration() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestApplyForwardedHeaders(t *testing.T) {
	tests := []struct {
		name            string
		options         Options
		incomingHeaders func() http.Header
		expectedHeaders map[string][]string
	}{
		{
			name:    "forward single header",
			options: Options{"forward-headers": "X-Request-ID"},
			incomingHeaders: func() http.Header {
				h := make(http.Header)
				h.Set("X-Request-ID", "12345")
				h.Set("User-Agent", "test-agent")
				return h
			},
			expectedHeaders: map[string][]string{
				"X-Request-Id": {"12345"},
			},
		},
		{
			name:    "forward multiple headers (comma-separated)",
			options: Options{"forward-headers": "X-Request-ID,User-Agent"},
			incomingHeaders: func() http.Header {
				h := make(http.Header)
				h.Set("X-Request-ID", "12345")
				h.Set("User-Agent", "test-agent")
				h.Set("Accept", "application/json")
				return h
			},
			expectedHeaders: map[string][]string{
				"X-Request-Id": {"12345"},
				"User-Agent":   {"test-agent"},
			},
		},
		{
			name:    "forward header with multiple values",
			options: Options{"forward-headers": "Cookie"},
			incomingHeaders: func() http.Header {
				h := make(http.Header)
				h.Add("Cookie", "session=abc")
				h.Add("Cookie", "token=xyz")
				return h
			},
			expectedHeaders: map[string][]string{
				"Cookie": {"session=abc", "token=xyz"},
			},
		},
		{
			name:    "forward non-existent header",
			options: Options{"forward-headers": "X-Missing-Header"},
			incomingHeaders: func() http.Header {
				h := make(http.Header)
				h.Set("User-Agent", "test-agent")
				return h
			},
			expectedHeaders: map[string][]string{},
		},
		{
			name:    "short form option",
			options: Options{"FH": "Authorization"},
			incomingHeaders: func() http.Header {
				h := make(http.Header)
				h.Set("Authorization", "Bearer token123")
				return h
			},
			expectedHeaders: map[string][]string{
				"Authorization": {"Bearer token123"},
			},
		},
		{
			name:    "no forward-header option",
			options: Options{},
			incomingHeaders: func() http.Header {
				h := make(http.Header)
				h.Set("X-Test", "value")
				return h
			},
			expectedHeaders: map[string][]string{},
		},
		{
			name:    "forward header with spaces in comma-separated list",
			options: Options{"forward-headers": "X-Trace-ID, X-Request-ID, Authorization"},
			incomingHeaders: func() http.Header {
				h := make(http.Header)
				h.Set("X-Trace-ID", "trace-123")
				h.Set("X-Request-ID", "req-456")
				h.Set("Authorization", "Bearer token")
				return h
			},
			expectedHeaders: map[string][]string{
				"X-Trace-Id":    {"trace-123"},
				"X-Request-Id":  {"req-456"},
				"Authorization": {"Bearer token"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outgoingHeaders := make(http.Header)
			incomingHeaders := tt.incomingHeaders()
			tt.options.ApplyForwardedHeaders(incomingHeaders, outgoingHeaders)

			// Check that all expected headers are present
			for key, expectedValues := range tt.expectedHeaders {
				actualValues := outgoingHeaders.Values(key)
				if len(actualValues) != len(expectedValues) {
					t.Errorf("Header %q has %d values, want %d", key, len(actualValues), len(expectedValues))
					continue
				}
				for i, expectedValue := range expectedValues {
					if actualValues[i] != expectedValue {
						t.Errorf("Header %q value[%d] = %q, want %q", key, i, actualValues[i], expectedValue)
					}
				}
			}

			// Check that no unexpected headers are present
			for key := range outgoingHeaders {
				if _, expected := tt.expectedHeaders[key]; !expected {
					t.Errorf("Unexpected header %q in outgoing headers", key)
				}
			}
		})
	}
}
