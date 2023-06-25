package main

type commandLog struct {
	Command  string     `json:"command,omitempty"`
	Output   reqLog     `json:"output,omitempty"`
	Url      string     `json:"url,omitempty"`
	Code     uint       `json:"code,omitempty"`
	Response *serverLog `json:"response,omitempty"`
	Error    string     `json:"error,omitempty"`
}

type requestLog struct {
	Method  string        `json:"method,omitempty"`
	Path    string        `json:"path,omitempty"`
	From    string        `json:"from,omitempty"`
	Size    int64         `json:"size,omitempty"`
	Process []*commandLog `json:"process,omitempty"`
}

type serverLog struct {
	Server  string      `json:"server,omitempty"`
	Iface   string      `json:"interface,omitempty"`
	Port    uint16      `json:"port-http,omitempty"`
	Ports   uint16      `json:"port-https,omitempty"`
	Request *requestLog `json:"request,omitempty"`
}
