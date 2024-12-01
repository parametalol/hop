package seqdiag

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/parametalol/hop/pkg/common"
)

type diagram struct {
	participants []string
	lines        []string
}

func Translate(sr json.RawMessage) (string, error) {
	if sr == nil {
		return "", nil
	}
	d := &diagram{}
	d.translate(sr)

	output := make([]string, 0, len(d.participants)+len(d.lines))
	for _, p := range d.participants {
		output = append(output, fmt.Sprintf("participant %s", p))
	}
	output = append(output, d.lines...)

	return strings.Join(output, "\n"), nil
}

func (d *diagram) translate(raw json.RawMessage) {
	var sr common.ServerLog
	if err := json.Unmarshal(([]byte)(raw), &sr); err != nil {
		fmt.Printf("Error decoding response")
		return
	}
	srv := sr.Server

	d.participants = append(d.participants, srv)

	if req := sr.Request; req != nil {
		d.participants = append(d.participants, req.From)
		d.lines = append(d.lines, fmt.Sprintf("%s->%s: %s %s (%d bytes)", req.From, srv, req.Method, req.Path, req.Size))
		for _, c := range req.Process {
			if c.Command != "" {
				d.lines = append(d.lines, fmt.Sprintf("%s->%s: Command %s", srv, srv, c.Command))
				d.lines = append(d.lines, fmt.Sprintf("note over %s:", srv))
				d.lines = append(d.lines, c.Output...)
				d.lines = append(d.lines, "end note")
			}
			if c.Url != "" {
				d.lines = append(d.lines, fmt.Sprintf("%s->%s: Call %s", srv, srv, c.Url))
			}
			if c.Error != nil {
				d.lines = append(d.lines, fmt.Sprintf("note over %s:\n%s\nend note", srv, c.Error.Err.Error()))
			}
			if c.Response != nil {
				d.translate(c.Response)
			}
		}
	}
}
