package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
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
	if addr[len(addr)-1] != '/' {
		addr += "/"
	}
	u, err := url.Parse(fmt.Sprintf("%s%s", addr, path))
	if err != nil {
		return nil, fmt.Errorf("cannot call %s: %s", addr, err.Error())
	}
	return u, nil
}

func (handler *hopHandler) hop(params *reqParams) *commandLog {
	clog := &commandLog{Command: "hop"}
	r := &clog.Output
	u := params.url
	clientReq, err := buildRequest(u, &params.headers, params.size)
	if err != nil {
		r.appendf("Couldn't make %s: %s\n", u, err.Error())
		return clog
	} else if clientReq == nil {
		r.appendf("Couldn't make %s by some reason\n", u)
		return clog
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
	clog.Code = uint(res.StatusCode)
	clog.Url = u.String()

	if err != nil {
		r.appendf("Couldn't call %s: %s\n", u, err.Error())
		return clog
	} else if res == nil {
		r.appendf("Couldn't call %s by some reason\n", u)
		return clog
	}
	defer res.Body.Close()
	if params.tlsInfo {
		appendTLSInfo(r, res.TLS, "client")
	}

	if params.showHeaders {
		var dump []byte
		dump, err = httputil.DumpResponse(res, false)
		if err == nil {
			for _, h := range strings.Split(string(dump), "\r\n") {
				r.append(h)
			}
		} else {
			r.appendln(err.Error())
		}
	}
	isHopServer := res.Header.Get("Server") == "hop"
	if isHopServer || res.ContentLength < 1024 {
		if body, err := io.ReadAll(res.Body); err == nil {
			if isHopServer {
				if err = json.Unmarshal(body, &clog.Response); err != nil {
					r.append(string(body))
				}
			} else {
				r.append(string(body))
			}
		} else {
			r.appendf("failed to read response body: %s", err)
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
	params.code.set(c)
	return clog
}
