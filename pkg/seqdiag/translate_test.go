package seqdiag

import (
	"encoding/json"
	"testing"

	"github.com/parametalol/hop/pkg/common"
	"github.com/parametalol/hop/pkg/tools"
	"github.com/stretchr/testify/assert"
)

func Test_diagram_translate(t *testing.T) {
	tests := map[string]struct {
		sr *common.ServerLog

		expected *diagram
	}{
		"one participant": {
			sr: &common.ServerLog{
				Server: "test",
			},
			expected: &diagram{
				participants: []string{"test"},
			},
		},
		"one command": {
			sr: &common.ServerLog{
				Server: "test",
				Request: &common.RequestLog{
					Method: "GET",
					Path:   "/-cmd",
					From:   "localhost",
					Size:   12,
					Process: []*common.CommandLog{
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
			data, _ := json.Marshal(tt.sr)
			actual.translate(data)

			assert.Equal(t, tt.expected, actual)
		})
	}
}
