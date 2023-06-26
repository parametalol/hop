package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	stdlog "log"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"time"

	"github.com/0x656b694d/hop/tlstools"
	"github.com/0x656b694d/hop/tools"
	log "github.com/sirupsen/logrus"
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
		ErrorLog:       stdlog.New(log.StandardLogger().Writer(), "http: ", 0),
	}
}

func (cfg *config) startHttpServer(client *hopClient, slog *serverLog, quit chan<- int) *http.Server {
	s := getServer(cfg.localhost, uint16(cfg.port_http))
	s.Handler = &hopHandler{cfg, client, slog}

	go func() {
		log.Info("Serving HTTP on ", cfg.localhost, ":", cfg.port_http)
		log.Info(s.ListenAndServe())
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
		serverCert, err = tlstools.SignWith(cfg.serviceNames, cfg.cacert, cfg.cakey)
		if err != nil {
			return nil, fmt.Errorf("couldn't sign with provided files: %w", err)
		}
	} else if cfg.key == "" && cfg.certificate == "" {
		var ca *x509.Certificate
		serverCert, ca, err = tlstools.GetSelfSigned(cfg.serviceNames)
		if err != nil {
			return nil, fmt.Errorf("couldn't self-sign server certificate: %w", err)
		}
		if ca != nil {
			pool.AddCert(ca)
		}
	}
	stls.TLSConfig = &tls.Config{
		ClientCAs: pool,
	}
	if serverCert != nil {
		stls.TLSConfig.Certificates = []tls.Certificate{*serverCert}
	}

	go func() {
		log.Info("Serving HTTPS on ", cfg.localhost, ":", cfg.port_https)
		log.Info(stls.ListenAndServeTLS(cfg.certificate, cfg.key))
		quit <- 4
	}()

	return stls, nil
}

func (handler *hopHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if handler.cfg.verbose {
		dump, err := httputil.DumpRequest(req, req.ContentLength < 1024)
		if err == nil {
			log.Debug(string(dump))
		} else {
			log.Error(err)
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
				Output: tools.ArrLog{fmt.Sprintf("Bad command: %s", err)},
			},
		)
	}
	if rp != nil {
		if rp.url != nil {
			log.Debug("sending request to ", rp.url)
			clog := handler.hop(rp)
			slog.Request.Process = append(slog.Request.Process, clog)
		}
		w.WriteHeader(int(rp.code.Set(200)))
		for h, v := range rp.rheaders {
			w.Header().Set(h, v)
		}
	}
	b, err := json.MarshalIndent(slog, "", "  ")
	if err != nil {
		log.Error("Error marshalling response: ", err.Error())
	} else {
		w.Write(b)
		log.Debug(string(b))
	}
}
