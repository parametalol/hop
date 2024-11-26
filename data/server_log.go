package data

import "github.com/0x656b694d/hop/pkg/tools"

type CommandLog struct {
	Command  string       `json:"command,omitempty"`
	Output   tools.ArrLog `json:"output,omitempty"`
	Url      string       `json:"url,omitempty"`
	Code     uint         `json:"code,omitempty"`
	Response *ServerLog   `json:"response,omitempty"`
	Error    string       `json:"error,omitempty"`
}

type RequestLog struct {
	Method  string        `json:"method,omitempty"`
	Path    string        `json:"path,omitempty"`
	From    string        `json:"from,omitempty"`
	Size    int64         `json:"size,omitempty"`
	Process []*CommandLog `json:"process,omitempty"`
}

type ServerLog struct {
	Server  string      `json:"server,omitempty"`
	Iface   string      `json:"interface,omitempty"`
	Port    uint16      `json:"port-http,omitempty"`
	Ports   uint16      `json:"port-https,omitempty"`
	Request *RequestLog `json:"request,omitempty"`
}
