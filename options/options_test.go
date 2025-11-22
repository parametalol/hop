package options

import (
	"slices"
	"testing"
	"time"
)

func TestOptionsValues(t *testing.T) {
	opts := make(Options)
	opts["method"] = "GET"
	opts["X"] = "POST"
	methods := slices.Collect(opts.values(Method))
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
			options:  Options{"s": "3"},
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
