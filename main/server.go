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
	"github.com/parametalol/hop/pkg/tools"
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
	if handler.cfg.loglevel > 2 {
		dump, err := httputil.DumpRequest(req, req.ContentLength < 1024)
		if err == nil {
			log.Debug(string(dump))
		} else {
			log.Error(err)
		}
	}

	hn, _ := os.Hostname()

	serverResponse := &common.ServerResponse{
		Server: hn,
		Iface:  handler.cfg.localhost,
		Port:   uint16(handler.cfg.port_http),
		Ports:  uint16(handler.cfg.port_https),
		InboundRequest: &common.Request{
			Path:    req.URL.RawPath,
			Method:  req.Method,
			From:    req.RemoteAddr,
			Headers: tools.JoinHeaders(req.Header),
		},
		Process: []*common.CommandLog{},
	}

	body, err := readBody(req.Body, req.Header)
	if err != nil {
		clog := &common.CommandLog{}
		clog.Err(err)
		serverResponse.Process = append(serverResponse.Process, clog)
	}
	body.Size = req.ContentLength
	serverResponse.InboundRequest.Body = body

	w.Header().Add("Server", "hop")
	if err := makeReq(handler.cfg, w, serverResponse, req); err != nil {
		if len(serverResponse.Process) > 0 && serverResponse.Process[len(serverResponse.Process)-1].Error != nil {
			w.WriteHeader(serverResponse.Process[len(serverResponse.Process)-1].Code)
		} else {
			w.WriteHeader(500)
		}
	}
	b, err := json.MarshalIndent(serverResponse, "", "  ")
	if err != nil {
		log.Error("Error marshalling response: ", err.Error())
		// http.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write(b)
		log.Debug(string(b))
	}
}
