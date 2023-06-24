package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"time"
)

type hopHandler struct {
	cfg    *config
	client *hopClient
}

func initServerTransport(roots *x509.CertPool) (*tls.Config, error) {
	log.Println("Initializing Server TLS")
	/*
		if len(certificate) != 0 && len(key) != 0 {
			tlsCert, err := tls.LoadX509KeyPair(certificate, key)
			if err != nil {
				return nil, fmt.Errorf("failed to load client certificate or key: %s", err)
			}
			roots.
			cfg.Certificates = []tls.Certificate{tlsCert}
		}
	*/
	return &tls.Config{
		ClientCAs: roots,
	}, nil
}

func getServer(host string, port uint16) *http.Server {
	return &http.Server{
		Addr:           net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
		ErrorLog:       log.New(os.Stdout, "http: ", 0),
	}
}

func (cfg *config) startHttpServer(client *hopClient, quit chan<- int) *http.Server {
	s := getServer(cfg.localhost, uint16(cfg.port_http))
	s.Handler = &hopHandler{cfg, client}

	go func() {
		fmt.Println("Serving HTTP on", cfg.localhost, cfg.port_http)
		fmt.Println(s.ListenAndServe())
		quit <- 3
	}()

	return s
}

func (cfg *config) startHttpsServer(client *hopClient, pool *x509.CertPool, quit chan<- int) *http.Server {
	if cfg.certificate == "" || cfg.key == "" {
		return nil
	}
	stls := getServer(cfg.localhost, uint16(cfg.port_https))
	stls.Handler = &hopHandler{cfg, client}

	if pool != nil {
		var err error
		stls.TLSConfig, err = initServerTransport(pool)
		if err != nil {
			return nil
		}
	}

	go func() {
		fmt.Println("Serving HTTPS on", cfg.localhost, cfg.port_https)
		fmt.Println(stls.ListenAndServeTLS(cfg.certificate, cfg.key))
		quit <- 4
	}()

	return stls
}

func (handler *hopHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	elapsed := func(start time.Time) {
		e := time.Since(start) / time.Millisecond
		hopDurations.WithLabelValues("uniform").Observe(float64(e))
	}
	defer elapsed(time.Now())
	if handler.cfg.verbose {
		dump, err := httputil.DumpRequest(req, req.ContentLength < 1024)
		if err == nil {
			log.Println(string(dump))
		} else {
			log.Println(err)
		}
	}

	var r reqLog

	hn, _ := os.Hostname()
	r.appendf("I'm %s, recieved %s %s from %s (%d bytes)", hn, req.Method, req.URL.RawPath, req.RemoteAddr, req.ContentLength)

	rp, err := makeReq(&r, req)
	if err != nil {
		w.WriteHeader(500)
		r.appendf("Bad command: %v", err)
		r.write(w)
		return
	}
	if rp != nil {
		if rp.url != nil {
			rp.code.set(handler.hop(&r, rp))
		}
		w.WriteHeader(int(rp.code.set(200)))
		for h, v := range rp.rheaders {
			w.Header().Set(h, v)
		}
	}
	r.write(w)
}
