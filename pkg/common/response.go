package common

import (
	"encoding/json"

	"github.com/parametalol/hop/pkg/tools"
)

type Body struct {
	Json json.RawMessage `json:"json,omitempty"`
	Text string          `json:"text,omitempty"`
	Size int64           `json:"size,omitempty"`
}

type Request struct {
	Method  string            `json:"method,omitempty"`
	Path    string            `json:"path,omitempty"`
	From    string            `json:"from,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    *Body             `json:"body,omitempty"`
}

type Response struct {
	Headers map[string]string `json:"headers,omitempty"`
	Code    int               `json:"code,omitempty"`
	Status  string            `json:"status,omitempty"`
	Body    *Body             `json:"body,omitempty"`
}

type OutbountRequest struct {
	Request
	Url             string           `json:"url,omitempty"`
	ConnectionState *ConnectionState `json:"connection-state,omitempty"`
	Response        *Response        `json:"response,omitempty"`
}

type CommandLog struct {
	Command         string           `json:"command,omitempty"`
	Output          tools.ArrLog     `json:"output,omitempty"`
	OutbountRequest *OutbountRequest `json:"outbound,omitempty"`
	Error           Error            `json:"error,omitempty"`
	Code            int              `json:"code,omitempty"`
}

func (c *CommandLog) Err(err error) *CommandLog {
	c.Error = &ErrorWrapper{err}
	return c
}

type ServerResponse struct {
	Server          string           `json:"server,omitempty"`
	Iface           string           `json:"interface,omitempty"`
	Port            uint16           `json:"port-http,omitempty"`
	Ports           uint16           `json:"port-https,omitempty"`
	ConnectionState *ConnectionState `json:"connection-state,omitempty"`
	InboundRequest  *Request         `json:"inbound,omitempty"`

	Process []*CommandLog `json:"process,omitempty"`
}
