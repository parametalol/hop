package common

import (
	"encoding/json"

	"github.com/parametalol/hop/pkg/tools"
)

type CommandLog struct {
	Command         string           `json:"command,omitempty"`
	Output          tools.ArrLog     `json:"output,omitempty"`
	Url             string           `json:"url,omitempty"`
	Code            int              `json:"code,omitempty"`
	ConnectionState *ConnectionState `json:"connection-state,omitempty"`
	Response        json.RawMessage  `json:"response,omitempty"`
	Error           Error            `json:"error,omitempty"`
}

func (c *CommandLog) Err(err error) *CommandLog {
	c.Error = &ErrorWrapper{err}
	return c
}

type RequestLog struct {
	Method  string        `json:"method,omitempty"`
	Path    string        `json:"path,omitempty"`
	From    string        `json:"from,omitempty"`
	Size    int64         `json:"size,omitempty"`
	Process []*CommandLog `json:"process,omitempty"`
}

type ServerLog struct {
	Server          string           `json:"server,omitempty"`
	Iface           string           `json:"interface,omitempty"`
	Port            uint16           `json:"port-http,omitempty"`
	Ports           uint16           `json:"port-https,omitempty"`
	ConnectionState *ConnectionState `json:"connection-state,omitempty"`
	Request         *RequestLog      `json:"request,omitempty"`
}
