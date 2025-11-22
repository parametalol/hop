package parser

import (
	"strings"
	"testing"
)

func TestParsePath(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantURL     string
		wantOptions map[string]string
		wantErr     bool
		errContains string
	}{
		{
			name:        "simple URL without options",
			input:       "/https://example.com",
			wantURL:     "https://example.com",
			wantOptions: map[string]string{},
			wantErr:     false,
		},
		{
			name:    "URL with single option",
			input:   "/-method=GET/https://example.com",
			wantURL: "https://example.com",
			wantOptions: map[string]string{
				"method": "GET",
			},
			wantErr: false,
		},
		{
			name:    "URL with multiple options",
			input:   "/-method=POST/-insecure=true/-timeout=30/https://example.com",
			wantURL: "https://example.com",
			wantOptions: map[string]string{
				"method":   "POST",
				"insecure": "true",
				"timeout":  "30",
			},
			wantErr: false,
		},
		{
			name:    "option without value defaults to true",
			input:   "/-insecure/https://example.com",
			wantURL: "https://example.com",
			wantOptions: map[string]string{
				"insecure": "true",
			},
			wantErr: false,
		},
		{
			name:        "URL with path",
			input:       "/https://example.com/api/v1/users",
			wantURL:     "https://example.com/api/v1/users",
			wantOptions: map[string]string{},
			wantErr:     false,
		},
		{
			name:    "URL with path and options",
			input:   "/-method=GET/-headers=Authorization:Bearer token/https://example.com/api/v1/users",
			wantURL: "https://example.com/api/v1/users",
			wantOptions: map[string]string{
				"method":  "GET",
				"headers": "Authorization:Bearer token",
			},
			wantErr: false,
		},
		{
			name:        "HTTP URL",
			input:       "/http://localhost:8080/test",
			wantURL:     "http://localhost:8080/test",
			wantOptions: map[string]string{},
			wantErr:     false,
		},
		{
			name:    "complex example with options before URL",
			input:   "/-method=GET/-insecure=true/https://example.com/api/path",
			wantURL: "https://example.com/api/path",
			wantOptions: map[string]string{
				"method":   "GET",
				"insecure": "true",
			},
			wantErr: false,
		},
		{
			name:    "URL encoded path segments",
			input:   "/-method=GET/https://example.com/hello%20world",
			wantURL: "https://example.com/hello%20world",
			wantOptions: map[string]string{
				"method": "GET",
			},
			wantErr: false,
		},
		{
			name:    "URL encoded option value",
			input:   "/-headers=Content-Type:%20application%2Fjson/https://example.com",
			wantURL: "https://example.com",
			wantOptions: map[string]string{
				"headers": "Content-Type: application/json",
			},
			wantErr: false,
		},
		{
			name:        "empty path",
			input:       "/",
			wantErr:     false,
			errContains: "empty path",
		},
		{
			name:        "completely empty",
			input:       "",
			wantErr:     false,
			errContains: "empty path",
		},
		{
			name:    "missing URL scheme",
			input:   "/example.com",
			wantURL: "http://example.com",
			wantErr: false,
		},
		{
			name:  "only options, no URL",
			input: "/-method=GET/-insecure=true",
			wantOptions: map[string]string{
				"method":   "GET",
				"insecure": "true",
			},
			wantErr: false,
		},
		{
			name:        "invalid URL encoding",
			input:       "/https://example.com/%zz",
			wantErr:     true,
			errContains: "invalid target URL",
		},
		{
			name:        "URL with query parameters",
			input:       "/https://example.com/search?q=test",
			wantURL:     "https://example.com/search?q=test",
			wantOptions: map[string]string{},
			wantErr:     false,
		},
		{
			name:    "URL with query parameters and options",
			input:   "/-method=POST/https://example.com/search?q=test",
			wantURL: "https://example.com/search?q=test",
			wantOptions: map[string]string{
				"method": "POST",
			},
			wantErr: false,
		},
		{
			name:        "URL with port",
			input:       "/https://example.com:8443/api",
			wantURL:     "https://example.com:8443/api",
			wantOptions: map[string]string{},
			wantErr:     false,
		},
		{
			name:    "multiple options without values",
			input:   "/-insecure/-k/https://example.com",
			wantURL: "https://example.com",
			wantOptions: map[string]string{
				"insecure": "true",
				"k":        "true",
			},
			wantErr: false,
		},
		{
			name:    "option with equals sign in value",
			input:   "/-headers=Authorization=Bearer=abc123/https://example.com",
			wantURL: "https://example.com",
			wantOptions: map[string]string{
				"headers": "Authorization=Bearer=abc123",
			},
			wantErr: false,
		},
		{
			name:        "URL with fragment",
			input:       "/https://example.com/page#section",
			wantURL:     "https://example.com/page#section",
			wantOptions: map[string]string{},
			wantErr:     false,
		},
		{
			name:        "URL with username and password",
			input:       "/https://user:pass@example.com/api",
			wantURL:     "https://user:pass@example.com/api",
			wantOptions: map[string]string{},
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePath(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParsePath() expected error but got nil")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ParsePath() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("ParsePath() unexpected error = %v", err)
				return
			}

			if got == nil {
				if tt.wantURL != "" {
					t.Errorf("ParsePath() returned nil, want URL %v", tt.wantURL)
				}
				if len(tt.wantOptions) > 0 {
					t.Errorf("ParsePath() returned nil, want Options %v", tt.wantOptions)
				}
				return
			}
			if got.TargetURL != tt.wantURL {
				t.Errorf("ParsePath() TargetURL = %v, want %v", got.TargetURL, tt.wantURL)
			}

			if len(got.Options) != len(tt.wantOptions) {
				t.Errorf("ParsePath() Options count = %v, want %v", len(got.Options), len(tt.wantOptions))
			}

			for key, wantValue := range tt.wantOptions {
				gotValue, ok := got.Options[key]
				if !ok {
					t.Errorf("ParsePath() missing option %q", key)
				} else if gotValue != wantValue {
					t.Errorf("ParsePath() option %q = %v, want %v", key, gotValue, wantValue)
				}
			}

			for key := range got.Options {
				if _, ok := tt.wantOptions[key]; !ok {
					t.Errorf("ParsePath() unexpected option %q with value %v", key, got.Options[key])
				}
			}
		})
	}
}
