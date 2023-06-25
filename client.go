package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
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
	log.Println("Initializing Client TLS")
	transport := &http.Transport{
		MaxIdleConns:    10,
		IdleConnTimeout: 30 * time.Second,
		TLSClientConfig: &tls.Config{
			RootCAs:            roots,
			InsecureSkipVerify: cfg.insecure,
		},
	}
	if len(cfg.certificate) != 0 && len(cfg.key) != 0 {
		tlsCert, err := tls.LoadX509KeyPair(cfg.certificate, cfg.key)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate or key: %s", err)
		}
		transport.TLSClientConfig.Certificates = []tls.Certificate{tlsCert}
	}
	if cfg.proxy_tunneling {
		transport.Proxy = proxy
	}

	return &hopClient{http.Client{Transport: transport}, cfg}, nil
}

func (c *hopClient) callURL(req *http.Request) (*http.Response, error) {
	if c.cfg.verbose {
		if dump, err := httputil.DumpRequest(req, req.ContentLength < 1024); err == nil {
			log.Println(string(dump))
		} else {
			log.Println(err)
		}
	}
	return c.Do(req)
}

type reqParams struct {
	url  *url.URL
	code resultCode

	size        int
	showHeaders bool
	tlsInfo     bool
	headers     map[string]string
	fheaders    []string
	rheaders    map[string]string
}

func newReqParams() *reqParams {
	return &reqParams{
		headers: map[string]string{
			"Content-type":    "text/plain",
			"Accept-Encoding": "text/plain",
		},
		rheaders: map[string]string{
			"Content-type": "text/plain",
		},
		fheaders: []string{},
	}
}

func buildURL(addr, path string) (*url.URL, error) {
	addr, err := url.PathUnescape(addr)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		addr = "http://" + addr
	}
	u, err := url.Parse(fmt.Sprintf("%s%s", addr, path))
	if err != nil {
		return nil, fmt.Errorf("cannot call %s: %s", addr, err.Error())
	}
	if u == nil {
		return nil, nil
	}
	if u.Scheme == "" {
		u.Scheme = "http"
	}
	return u, nil
}

func (handler *hopHandler) hop(r *reqLog, params *reqParams) int {
	u := params.url
	clientReq, err := buildRequest(u, &params.headers, params.size)
	if err != nil {
		r.appendf("Couldn't make %s: %s\n", u, err.Error())
		return 0
	} else if clientReq == nil {
		r.appendf("Couldn't make %s by some reason\n", u)
		return 0
	}
	if proxy_url, _ := proxy(clientReq); proxy_url != nil {
		if handler.cfg.verbose {
			log.Printf("Using proxy: %s", proxy_url)
		}
		if !handler.cfg.proxy_tunneling {
			clientReq.URL.Host = proxy_url.Host
			r.appendf("Overriding url: %s", clientReq.URL)
		}
		if params.showHeaders {
			r.appendf("Using proxy: %s", proxy_url)
		}
	}
	res, err := handler.client.callURL(clientReq)
	if err != nil {
		r.appendf("Couldn't call %s: %s\n", u, err.Error())
		return 0
	} else if res == nil {
		r.appendf("Couldn't call %s by some reason\n", u)
		return 0
	}
	defer res.Body.Close()
	r.appendf("Called %s: %s", u, res.Status)
	if params.tlsInfo {
		appendTLSInfo(r, res.TLS, "client")
	}

	if params.showHeaders {
		var dump []byte
		dump, err = httputil.DumpResponse(res, res.ContentLength < 1024)
		if err == nil {
			for _, line := range strings.Split(string(dump), "\n") {
				r.appendf(".\t%s", line)
			}
			if res.ContentLength >= 1024 {
				r.appendf(".\t<%d bytes>", res.ContentLength)
			}
		} else {
			r.appendln(err.Error())
		}
	}
	c := res.StatusCode

	for _, h := range params.fheaders {
		v := res.Header.Get(h)
		r.appendf("Back forwarding header %s: %s", h, v)
		if len(v) > 0 {
			params.rheaders[h] = v
		}
	}
	if c == 0 && err != nil {
		c = 500
	}
	return c
}
