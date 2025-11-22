package parser

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/parametalol/hop/options"
)

type ParsedRequest struct {
	TargetURL string
	Options   options.Options
}

// ParsePath parses a path with options before the URL
// Example: /-method=GET/-insecure=true/https://example.com/api/v1/users
// Returns the target URL (with path preserved) and parsed options
func ParsePath(path string) (*ParsedRequest, error) {
	// Remove leading slash
	path = strings.TrimPrefix(path, "/")

	if path == "" {
		return nil, nil
	}

	// Split by /
	segments := strings.Split(path, "/")
	if len(segments) == 0 {
		return nil, fmt.Errorf("no segments in path")
	}

	o := make(options.Options)
	urlStartIndex := -1

	// Parse options at the beginning until we hit a non-option segment
	for i, segment := range segments {
		// URL decode the segment
		decoded, err := url.PathUnescape(segment)
		if err != nil {
			return nil, fmt.Errorf("failed to decode segment %q: %w", segment, err)
		}

		// Check if this is an option (starts with -)
		if optStr, isOption := strings.CutPrefix(decoded, "-"); isOption {
			// Parse the option
			parts := strings.SplitN(optStr, "=", 2)
			if len(parts) == 2 {
				o[parts[0]] = parts[1]
			} else {
				// Option without value (e.g., -insecure)
				o[parts[0]] = "true"
			}
			if !options.Check(parts[0]) {
				return nil, fmt.Errorf("unknown option %q", parts[0])
			}
		} else {
			// First non-option segment - this is where the URL starts
			urlStartIndex = i
			break
		}
	}

	// If we only found options and no URL
	if urlStartIndex == -1 {
		return &ParsedRequest{
			Options: o,
		}, nil
	}

	// Join everything from the URL start onwards
	remainingPath := strings.Join(segments[urlStartIndex:], "/")

	// Check if the path starts with a scheme by looking for "://"
	targetURL := remainingPath
	if !strings.Contains(remainingPath, "://") {
		// No scheme found, add http://
		targetURL = "http://" + remainingPath
	}

	// Validate that we have a valid URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL %q: %w", targetURL, err)
	}

	return &ParsedRequest{
		TargetURL: parsedURL.String(),
		Options:   o,
	}, nil
}
