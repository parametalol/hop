package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/parametalol/hop/pkg/common"
	"github.com/parametalol/hop/pkg/tlstools"
	"github.com/parametalol/hop/pkg/tools"
	log "github.com/sirupsen/logrus"
)

func proxy(req *http.Request) (*url.URL, error) {
	switch req.URL.Scheme {
	case "http":
		return http_proxy_url, nil
	case "https":
		return https_proxy_url, nil
	}
	return http.ProxyFromEnvironment(req)
}

type hopClient struct {
	http.Client
	cfg *config
}

func (cfg *config) getClient() (*hopClient, error) {
	transport := &http.Transport{
		MaxIdleConns:        10,
		IdleConnTimeout:     10 * time.Minute,
		TLSHandshakeTimeout: 10 * time.Minute,
		TLSClientConfig: &tls.Config{
			RootCAs:            tlstools.GetCertPool(cfg.cacerts...),
			InsecureSkipVerify: cfg.insecure,
		},
	}
	if cfg.mtls {
		if cfg.certificate != "" && cfg.key != "" {
			tlsCert, err := tls.LoadX509KeyPair(cfg.certificate, cfg.key)
			if err != nil {
				return nil, fmt.Errorf("failed to load client certificate or private key: %s", err)
			}
			transport.TLSClientConfig.Certificates = []tls.Certificate{tlsCert}
		} else {
			log.Debug("adding client certificate for mTLS")
			transport.TLSClientConfig.Certificates = []tls.Certificate{*cfg.getCert("Hop client")}
		}
	}
	if cfg.proxy_tunneling {
		transport.Proxy = proxy
	}

	return &hopClient{http.Client{Transport: transport}, cfg}, nil
}

func (c *hopClient) callURL(req *http.Request, rtrip bool) (*http.Response, error) {
	if c.cfg.loglevel > 2 {
		if dump, err := httputil.DumpRequest(req, req.ContentLength < 1024); err == nil {
			log.Debug(string(dump))
		} else {
			log.Error(err)
		}
	}
	if rtrip {
		return c.Client.Transport.RoundTrip(req)
	}
	return c.Do(req)
}

type reqParams struct {
	url  *url.URL
	code tools.ResultCode

	size        int
	showHeaders bool
	tlsInfo     bool
	method      string
	rtrip       bool
	headers     map[string]string
	fheaders    []string
	rheaders    map[string]string
}

func newReqParams() *reqParams {
	return &reqParams{
		method: http.MethodGet,
		headers: map[string]string{
			"Content-type":    "application/json",
			"Accept-Encoding": "application/json",
			"User-Agent":      "hop",
		},
		rheaders: map[string]string{
			"Content-type": "application/json",
		},
		fheaders: []string{},
	}
}

func buildRequest(p *reqParams) (*http.Request, error) {
	log.Infof("Call %s, sending %d bytes and %v", p.url, p.size, p.headers)
	payload := bytes.Repeat([]byte{'X'}, p.size)

	if p.method == "" {
		p.method = http.MethodGet
	}
	req, err := http.NewRequest(p.method, p.url.String(), bytes.NewReader(payload))
	if err != nil || req == nil {
		return nil, err
	}

	for h, v := range p.headers {
		if strings.ToLower(h) == "host" {
			req.Host = v
		} else {
			req.Header.Set(h, v)
		}
	}
	return req, err
}

func readBody(body io.ReadCloser, headers http.Header) (*common.Body, error) {
	defer body.Close()
	var err error
	data, err := io.ReadAll(body)
	switch strings.Split(headers.Get("Content-Type"), ";")[0] {
	case "application/json":
		return &common.Body{
			Json: data,
		}, err
	case "text/plain":
		return &common.Body{
			Text: string(data),
		}, err
	default:
		return &common.Body{}, err
	}
}

func processResponse(clog *common.CommandLog, res *http.Response, params *reqParams) {
	clog.OutbountRequest.Response = &common.Response{
		Code:   res.StatusCode,
		Status: res.Status,
	}
	clog.Code = res.StatusCode
	params.code.Set(res.StatusCode)
	if params.tlsInfo {
		clog.OutbountRequest.ConnectionState = (*common.ConnectionState)(res.TLS)
	}
	if params.showHeaders {
		clog.OutbountRequest.Response.Headers = tools.JoinHeaders(res.Header)
	}
	body, err := readBody(res.Body, res.Header)
	if err != nil {
		clog.Err(err)
	}
	body.Size = res.ContentLength
	clog.OutbountRequest.Response.Body = body
}
