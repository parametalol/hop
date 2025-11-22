package parser

import (
	"fmt"
	"net/url"
	"strings"
	"text/scanner"

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

	var s scanner.Scanner
	s.Init(strings.NewReader(path))
	s.Whitespace = 0 // Don't skip any characters
	s.IsIdentRune = func(ch rune, i int) bool {
		// Accept any character except '/' as part of a segment
		return ch != '/'
	}

	o := make(options.Options)
	var urlStartOffset int

	// Scan segments separated by '/'
	for {
		tok := s.Scan()
		if tok == scanner.EOF {
			break
		}

		segment := s.TokenText()

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
			urlStartOffset = s.Pos().Offset - len(segment)
			break
		}

		// Consume the '/' if present
		if s.Peek() == '/' {
			s.Next()
		}
	}

	// If we only found options and no URL
	if urlStartOffset == 0 && len(o) > 0 {
		return &ParsedRequest{
			Options: o,
		}, nil
	}

	// Everything from urlStartOffset onwards is the URL
	remainingPath := path[urlStartOffset:]

	// Check if the path starts with a scheme by looking for "://"
	targetURL := remainingPath
	if !strings.Contains(remainingPath, "://") {
		// No scheme found, add http://
		targetURL = "http://" + remainingPath
	}

	// Validate that we have a valid URL
	if _, err := url.Parse(targetURL); err != nil {
		return nil, fmt.Errorf("invalid target URL %q: %w", targetURL, err)
	}

	return &ParsedRequest{
		TargetURL: targetURL,
		Options:   o,
	}, nil
}
