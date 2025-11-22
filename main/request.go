package main

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/parametalol/hop/pkg/common"
	"github.com/parametalol/hop/pkg/tools"
)

func makeReq(cfg *config, w http.ResponseWriter, response *common.ServerResponse, req *http.Request) error {
	rp, err := prepareRequest(req.URL.EscapedPath(), req, response)
	if rp == nil {
		return err
	}
	clog := hop(cfg, rp)
	response.Process = append(response.Process, clog)
	w.WriteHeader(int(rp.code.Set(200)))
	for h, v := range rp.rheaders {
		w.Header().Set(h, v)
	}
	return nil
}

// prepareRequest runs all current commands and returns the next hop params.
func prepareRequest(path string, req *http.Request, response *common.ServerResponse) (*reqParams, error) {
	rp := newReqParams()
	ctx := &cmdContext{}

	path = strings.TrimPrefix(path, "/")

	var command string
	for strings.HasPrefix(path, "-") {
		command, path = tools.Pop(path)
		clog := execCommand(ctx, req, rp, command)
		response.Process = append(response.Process, clog)
		if clog.Error != nil {
			return nil, clog.Error.Err
		}
	}
	if req != nil && rp.tlsInfo {
		response.ConnectionState = (*common.ConnectionState)(req.TLS)
	}
	var err error
	if command == "" {
		if path != "" {
			rp.url, err = url.Parse(path)
			return rp, err
		}
		return nil, err
	}
	if ctx.skip {
		clog := &common.CommandLog{}
		clog.Output.Appendf("Skipping call to %s", command)
		response.Process = append(response.Process, clog)
		return nil, nil
	}
	if rp.url, err = tools.BuildURL(command, path); err != nil {
		return nil, err
	}
	return rp, nil
}
