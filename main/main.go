package main

import (
	"context"

	"net/url"

	"github.com/parametalol/hop/pkg/tlstools"
	log "github.com/sirupsen/logrus"
)

var (
	quit = make(chan int)

	http_proxy_url  *url.URL
	https_proxy_url *url.URL
)

func main() {

	cfg, args := getConfig()
	if cfg == nil {
		log.Exit(0)
	}

	log.SetLevel(log.Level(cfg.loglevel))
	tlstools.Init()

	var err error
	if len(cfg.https_proxy) != 0 {
		https_proxy_url, err = url.Parse(cfg.https_proxy)
	}
	if err != nil {
		log.Panicf("failed to parse parameters: %s", err)
	}
	if len(cfg.http_proxy) != 0 {
		http_proxy_url, err = url.Parse(cfg.http_proxy)
	}
	if err != nil {
		log.Panicf("failed to parse parameters: %s", err)
	}

	if len(args) == 1 {
		doHop(cfg, args[0])
		return
	}

	s := cfg.startHttpServer(quit)
	stls, err := cfg.startHttpsServer(quit)
	if err != nil {
		log.Errorf("failed to start HTTPS server: %v", err)
	}

	for code := range quit {
		log.Debugf("Received exit command code %d", code)
		switch code {
		case 2:
			panic("Rabbits are coming!")
		}
	}

	log.Info("Shutting down")
	err = s.Shutdown(context.Background())
	if err != nil {
		log.Error("HTTP server error:", err)
	}
	<-quit // wait for the server to stop.
	if stls != nil {
		err = stls.Shutdown(context.Background())
		if err != nil {
			log.Error("HTTPS server error:", err)
		}
		<-quit // wait for the server to stop.
	}
	if err != nil {
		log.Error("Failed to stop gracefully")
	} else {
		log.Info("Exiting normally")
	}
}
