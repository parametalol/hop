package main

import (
	"crypto/tls"
	"encoding/json"
	stdlog "log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"time"

	"github.com/parametalol/hop/pkg/common"
	"github.com/parametalol/hop/pkg/tlstools"
	log "github.com/sirupsen/logrus"
)

type hopHandler struct {
	cfg *config
}

func getServer(host string, port uint16) *http.Server {
	return &http.Server{
		Addr:              net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)),
		ReadTimeout:       10 * time.Minute,
		WriteTimeout:      10 * time.Minute,
		ReadHeaderTimeout: 10 * time.Minute,
		IdleTimeout:       10 * time.Minute,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          stdlog.New(log.StandardLogger().Writer(), "http: ", 0),
	}
}

func (cfg *config) startHttpServer(quit chan<- int) *http.Server {
	s := getServer(cfg.localhost, uint16(cfg.port_http))
	s.Handler = &hopHandler{cfg}

	go func() {
		log.Info("Serving HTTP on ", cfg.localhost, ":", cfg.port_http)
		log.Info(s.ListenAndServe())
		quit <- 3
	}()

	return s
}

func (cfg *config) startHttpsServer(quit chan<- int) (*http.Server, error) {
	stls := getServer(cfg.localhost, uint16(cfg.port_https))
	stls.Handler = &hopHandler{cfg}

	stls.ErrorLog = stdlog.New(log.StandardLogger().Writer(), "tls", 0)
	stls.TLSConfig = &tls.Config{
		ClientCAs:    tlstools.GetCertPool(cfg.cacerts...),
		ClientAuth:   tls.VerifyClientCertIfGiven,
		Certificates: []tls.Certificate{*cfg.getCert("Hop server")},
	}

	go func() {
		log.Info("Serving HTTPS on ", cfg.localhost, ":", cfg.port_https)
		log.Info(stls.ListenAndServeTLS(cfg.certificate, cfg.key))
		quit <- 4
	}()

	return stls, nil
}

func (handler *hopHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Header.Get("Accept") == "text/seqdiag" {
		handler.cfg.seqdiag = true
	}

	if handler.cfg.loglevel > 2 {
		dump, err := httputil.DumpRequest(req, req.ContentLength < 1024)
		if err == nil {
			log.Debug(string(dump))
		} else {
			log.Error(err)
		}
	}

	hn, _ := os.Hostname()
	response := &common.ServerLog{
		Server: hn,
		Iface:  handler.cfg.localhost,
		Port:   uint16(handler.cfg.port_http),
		Ports:  uint16(handler.cfg.port_https),
		Request: &common.RequestLog{
			Path:    req.URL.RawPath,
			Method:  req.Method,
			From:    req.RemoteAddr,
			Size:    req.ContentLength,
			Process: []*common.CommandLog{},
		},
	}

	rp, err := makeReq(response, req)
	w.Header().Add("Server", "hop")
	if err != nil {
		if len(response.Request.Process) > 0 && response.Request.Process[len(response.Request.Process)-1].Error != nil {
			w.WriteHeader(response.Request.Process[len(response.Request.Process)-1].Code)
		} else {
			w.WriteHeader(500)
		}
	}
	if rp != nil {
		if rp.url != nil {
			log.Debug("sending request to ", rp.url)
			clog := handler.hop(rp)
			response.Request.Process = append(response.Request.Process, clog)
		}
		w.WriteHeader(int(rp.code.Set(200)))
		for h, v := range rp.rheaders {
			w.Header().Set(h, v)
		}
	}
	b, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		log.Error("Error marshalling response: ", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write(b)
		log.Debug(string(b))
	}
}
