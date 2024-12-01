package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
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
		headers: map[string]string{
			"Content-type":    "text/plain",
			"Accept-Encoding": "text/plain",
			"User-Agent":      "hop",
		},
		rheaders: map[string]string{
			"Content-type": "text/plain",
		},
		fheaders: []string{},
	}
}

func BuildRequest(url *url.URL, method string, headers map[string]string, size int) (*http.Request, error) {
	log.Infof("Call %s, sending %d bytes and %v", url, size, headers)
	payload := bytes.Repeat([]byte{'X'}, size)

	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequest(method, url.String(), bytes.NewReader(payload))
	if err != nil || req == nil {
		return nil, err
	}

	for h, v := range headers {
		if strings.ToLower(h) == "host" {
			req.Host = v
		} else {
			req.Header.Set(h, v)
		}
	}
	return req, err
}

func (handler *hopHandler) hop(params *reqParams) *common.CommandLog {
	clog := &common.CommandLog{Command: "hop"}
	r := &clog.Output
	u := params.url
	clientReq, err := BuildRequest(u, params.method, params.headers, params.size)
	if err != nil {
		r.Appendf("Couldn't make %s: %s\n", u, err.Error())
		return clog
	} else if clientReq == nil {
		r.Appendf("Couldn't make %s by some reason\n", u)
		return clog
	}
	if proxy_url, _ := proxy(clientReq); proxy_url != nil {
		log.Infof("Using proxy: %s", proxy_url)
		if !handler.cfg.proxy_tunneling {
			clientReq.URL.Host = proxy_url.Host
			r.Appendf("Overriding url: %s", clientReq.URL)
		}
		if params.showHeaders {
			r.Appendf("Using proxy: %s", proxy_url)
		}
	}

	client, err := handler.cfg.getClient()
	if err != nil {
		log.Panic(err)
	}
	res, err := client.callURL(clientReq, params.rtrip)
	if err != nil {
		log.Error(err)
		r.Appendf("Couldn't call %s: %s\n", u, err.Error())
		return clog
	}
	if res == nil {
		r.Appendf("Couldn't call %s by some reason\n", u)
		return clog
	}
	clog.Code = res.StatusCode
	clog.Url = u.String()
	err = treatResponse(clog, res, params)

	c := res.StatusCode

	for _, h := range params.fheaders {
		v := res.Header.Get(h)
		r.Appendf("Back forwarding header %s: %s", h, v)
		if len(v) > 0 {
			params.rheaders[h] = v
		}
	}
	if c == 0 && err != nil {
		c = 500
	}
	params.code.Set(c)
	return clog
}

func treatResponse(clog *common.CommandLog, res *http.Response, params *reqParams) error {
	r := &clog.Output
	var err error
	defer res.Body.Close()
	if params.tlsInfo {
		clog.ConnectionState = (*common.ConnectionState)(res.TLS)
	}

	if params.showHeaders {
		var dump []byte
		dump, err = httputil.DumpResponse(res, false)
		r.Append("== Response headers ==")
		if err == nil {
			for _, h := range strings.Split(string(dump), "\r\n") {
				if h != "" {
					r.Append("  " + h)
				}
			}
		} else {
			r.Appendln(err.Error())
		}
	}
	if res.Header.Get("Content-Type") == "application/json" {
		if err := json.NewDecoder(res.Body).Decode(&clog.Response); err != nil {
			clog.Err(err)
		}
	}
	return err
}
