package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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

	log *serverLog
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

func (cfg *config) startHttpServer(client *hopClient, slog *serverLog, quit chan<- int) *http.Server {
	s := getServer(cfg.localhost, uint16(cfg.port_http))
	s.Handler = &hopHandler{cfg, client, slog}

	go func() {
		fmt.Println("Serving HTTP on", cfg.localhost, cfg.port_http)
		fmt.Println(s.ListenAndServe())
		quit <- 3
	}()

	return s
}

func (cfg *config) startHttpsServer(client *hopClient, pool *x509.CertPool, slog *serverLog, quit chan<- int) (*http.Server, error) {
	stls := getServer(cfg.localhost, uint16(cfg.port_https))
	stls.Handler = &hopHandler{cfg, client, slog}

	var err error
	var serverCert *tls.Certificate
	if cfg.cacert != "" && cfg.cakey != "" {
		serverCert, err = signWith(cfg.serviceNames, cfg.cacert, cfg.cakey)
		if err != nil {
			return nil, fmt.Errorf("couldn't sign with provided files: %w", err)
		}
	} else if cfg.key == "" && cfg.certificate == "" {
		var ca *x509.Certificate
		serverCert, ca, err = getSelfSigned(cfg.serviceNames)
		if err != nil {
			return nil, fmt.Errorf("couldn't self-sign server certificate: %w", err)
		}
		if ca != nil {
			pool.AddCert(ca)
		}
	}
	stls.TLSConfig = &tls.Config{
		ClientCAs:    pool,
		Certificates: []tls.Certificate{*serverCert},
	}

	go func() {
		fmt.Println("Serving HTTPS on", cfg.localhost, cfg.port_https)
		fmt.Println(stls.ListenAndServeTLS(cfg.certificate, cfg.key))
		quit <- 4
	}()

	return stls, nil
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

	slog := *handler.log

	slog.Request = &requestLog{
		Path:   req.URL.RawPath,
		Method: req.Method,
		From:   req.RemoteAddr,
		Size:   req.ContentLength,
	}

	slog.Request.Process = make([]*commandLog, 0)

	rp, err := makeReq(slog.Request, req)
	w.Header().Add("Server", "hop")
	if err != nil {
		w.WriteHeader(500)
		slog.Request.Process = append(slog.Request.Process,
			&commandLog{
				Code:   500,
				Output: reqLog{fmt.Sprintf("Bad command: %s", err)},
			},
		)
	}
	if rp != nil {
		if rp.url != nil {
			clog := handler.hop(rp)
			slog.Request.Process = append(slog.Request.Process, clog)
		}
		w.WriteHeader(int(rp.code.set(200)))
		for h, v := range rp.rheaders {
			w.Header().Set(h, v)
		}
	}
	b, err := json.MarshalIndent(slog, "", "  ")
	if err != nil {
		log.Printf("Error marshalling response: %s", err)
	} else {
		w.Write(b)
	}
}
