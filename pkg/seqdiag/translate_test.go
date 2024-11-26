package seqdiag

import (
	"testing"

	"github.com/parametalol/hop/data"
	"github.com/parametalol/hop/pkg/tools"
	"github.com/stretchr/testify/assert"
)

func Test_diagram_translate(t *testing.T) {
	tests := map[string]struct {
		sr *data.ServerLog

		expected *diagram
	}{
		"one participant": {
			sr: &data.ServerLog{
				Server: "test",
			},
			expected: &diagram{
				participants: []string{"test"},
			},
		},
		"one command": {
			sr: &data.ServerLog{
				Server: "test",
				Request: &data.RequestLog{
					Method: "GET",
					Path:   "/-cmd",
					From:   "localhost",
					Size:   12,
					Process: []*data.CommandLog{
						{Command: "-cmd", Output: tools.ArrLog{"line1", "line2"}},
					},
				},
			},
			expected: &diagram{
				participants: []string{"test", "localhost"},
				lines: []string{
					"localhost->test: GET /-cmd (12 bytes)",
					"test->test: Command -cmd",
					"note over test:",
					"line1",
					"line2",
					"end note"},
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			actual := &diagram{}
			actual.translate(tt.sr)

			assert.Equal(t, tt.expected, actual)
		})
	}
}
