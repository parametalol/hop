package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/parametalol/hop/pkg/common"
	"github.com/parametalol/hop/pkg/tools"
	log "github.com/sirupsen/logrus"
)

func doHop(cfg *config, args []string) {
	response := &common.ServerResponse{}
	u, err := url.Parse(args[0])
	if err != nil {
		log.Panic(err)
	}
	rp, err := prepareRequest(u, nil, response)
	if rp == nil {
		log.Panic(err)
		return
	}
	clog := hop(cfg, rp)
	response.Process = append(response.Process, clog)
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	if err = e.Encode(response); err != nil {
		log.Panic(err)
	}
}

func hop(cfg *config, params *reqParams) *common.CommandLog {
	clog := &common.CommandLog{
		Command: "hop",
	}

	r := &clog.Output
	clientReq, err := buildRequest(params)
	if err != nil {
		return clog.Err(fmt.Errorf("couldn't make %s: %w", params.url, err))
	}
	clog.OutbountRequest = &common.OutbountRequest{
		Url: params.url.String(),
		Request: common.Request{
			Method:  clientReq.Method,
			Path:    clientReq.URL.Path,
			Headers: tools.JoinHeaders(clientReq.Header),
			Body: &common.Body{
				Size: clientReq.ContentLength,
			},
		},
	}

	if proxy_url, _ := proxy(clientReq); proxy_url != nil {
		log.Infof("Using proxy: %s", proxy_url)
		if !cfg.proxy_tunneling {
			clientReq.URL.Host = proxy_url.Host
			r.Appendf("Overriding url: %s", clientReq.URL)
		}
		if params.showHeaders {
			r.Appendf("Using proxy: %s", proxy_url)
		}
	}

	client, err := cfg.getClient()
	if err != nil {
		log.Panic(err)
	}
	res, err := client.callURL(clientReq, params.rtrip)
	if err != nil {
		return clog.Err(fmt.Errorf("couldn't call %s: %s", params.url, err.Error()))
	}
	processResponse(clog, res, params)
	for _, h := range params.fheaders {
		v := res.Header.Get(h)
		r.Appendf("Back forwarding header %s: %s", h, v)
		if len(v) > 0 {
			params.rheaders[h] = v
		}
	}
	return clog
}
