package common

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJsonMarhalling(t *testing.T) {
	sr := ServerResponse{
		Server:         "hop",
		Iface:          "0.0.0.0",
		InboundRequest: &Request{},
		Process: []*CommandLog{{
			Command: "test",
		}, {
			OutbountRequest: &OutbountRequest{
				Request: Request{
					Method: "GET",
					Path:   "path",
					Headers: map[string]string{
						"Header": "Value",
					},
				},
			},
		}},
	}
	data, err := json.MarshalIndent(sr, "", "  ")
	require.NoError(t, err)
	assert.Equal(t, `{
  "server": "hop",
  "interface": "0.0.0.0",
  "inbound": {},
  "process": [
    {
      "command": "test"
    },
    {
      "outbound": {
        "method": "GET",
        "path": "path",
        "headers": {
          "Header": "Value"
        }
      }
    }
  ]
}`, string(data))
}
