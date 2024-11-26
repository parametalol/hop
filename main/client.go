package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/parametalol/hop/data"
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

func (cfg *config) getClient(roots *x509.CertPool) (*hopClient, error) {
	transport := &http.Transport{
		MaxIdleConns:        10,
		IdleConnTimeout:     10 * time.Minute,
		TLSHandshakeTimeout: 10 * time.Minute,
		TLSClientConfig: &tls.Config{
			RootCAs:            roots,
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
	if c.cfg.verbose {
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

func (handler *hopHandler) hop(params *reqParams) *data.CommandLog {
	clog := &data.CommandLog{Command: "hop"}
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
		if handler.cfg.verbose {
			log.Infof("Using proxy: %s", proxy_url)
		}
		if !handler.cfg.proxy_tunneling {
			clientReq.URL.Host = proxy_url.Host
			r.Appendf("Overriding url: %s", clientReq.URL)
		}
		if params.showHeaders {
			r.Appendf("Using proxy: %s", proxy_url)
		}
	}
	res, err := handler.client.callURL(clientReq, params.rtrip)
	if err != nil {
		log.Error(err)
		r.Appendf("Couldn't call %s: %s\n", u, err.Error())
		return clog
	}
	if res == nil {
		r.Appendf("Couldn't call %s by some reason\n", u)
		return clog
	}
	clog.Code = uint(res.StatusCode)
	clog.Url = u.String()
	err = TreatResponse(clog, res, params, handler.cfg.insecure)

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

func TreatResponse(clog *data.CommandLog, res *http.Response, params *reqParams, insecure bool) error {
	r := &clog.Output
	var err error
	defer res.Body.Close()
	if params.tlsInfo {
		r.Append("== Response TLS info ==")
		tlstools.AppendTLSInfo(r, res.TLS, insecure)
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
	isHopServer := res.Header.Get("Server") == "hop"
	if isHopServer || res.ContentLength < 1024 {
		if body, err := io.ReadAll(res.Body); err == nil {
			if isHopServer {
				if err = json.Unmarshal(body, &clog.Response); err != nil {
					r.Append(string(body))
				}
			} else {
				r.Append(string(body))
			}
		} else {
			r.Appendf("failed to read response body: %s", err)
		}
	}
	return err
}
