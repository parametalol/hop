package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/parametalol/hop/pkg/common"
	"github.com/parametalol/hop/pkg/seqdiag"
	"github.com/parametalol/hop/pkg/tlstools"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
)

var (
	help = map[string][2]string{
		"-code":    {"N", "responde with HTTP code N"},
		"-crash":   {"", "stops the server without a response"},
		"-fheader": {"H", "forward incoming header H to the following request"},
		"-header":  {"H=V", "add header H: V to the following request"},
		"-help":    {"", "return help message"},
		"-if":      {"H=V", "execute next command if header H contains substring V"},
		"-info":    {"", "return some info about the request"},
		"-method":  {"M", "use M method for the request"},
		"-rtrip":   {"", "do a round-trip request (no follow redirects and such)"},
		"-tls":     {"", "include verbose TLS info"},
		"-not":     {"", "reverts the effect of the next boolean command (if, on)"},
		"-on":      {"H", "executes next command if the server host name contains substring H"},
		"-quit":    {"", "stops the server with a nice response"},
		"-rheader": {"H=V", "add header H: V to the reponse"},
		"-rnd":     {"P", "execute next command with P% probability"},
		"-rsize":   {"B", "add B bytes of payload to the response"},
		"-size":    {"B", "add B bytes of payload to the following query"},
		"-wait":    {"T", "wait for T ms before response"},
		"-env":     {"V", "return the value of an environment variable"},
	}

	quit = make(chan int)

	http_proxy_url  *url.URL
	https_proxy_url *url.URL
)

type config struct {
	insecure        bool
	loglevel        uint8
	port_http       uint
	port_https      uint
	http_proxy      string
	https_proxy     string
	proxy_tunneling bool
	cacerts         []string
	cacert          string
	cakey           string
	certificate     string
	mtls            bool
	key             string
	localhost       string
	serviceNames    []string
	seqdiag         bool
}

func getConfig() (*config, []string) {
	var port_http uint64 = 80
	var port_https uint64 = 443
	var err error
	if s := os.Getenv("PORT"); len(s) != 0 {
		port_http, err = strconv.ParseUint(s, 10, 16)
		if err != nil {
			log.Panic(err)
		}
	}
	if s := os.Getenv("PORT_HTTPS"); len(s) != 0 {
		port_https, err = strconv.ParseUint(s, 10, 16)
		if err != nil {
			log.Panic(err)
		}
	}

	cfg := &config{}

	// .NewFlagSet("hop", flag.ContinueOnError)
	flag.Uint8VarP(&cfg.loglevel, "loglevel", "v", 1, "log level [0..6]")
	flag.StringVarP(&cfg.localhost, "interface", "i", "0.0.0.0", "the interface to listen on")
	flag.UintVarP(&cfg.port_http, "port-http", "", uint(port_http), "port HTTP")
	flag.BoolVarP(&cfg.insecure, "insecure", "k", false, "client to skip TLS verification")
	flag.BoolVarP(&cfg.seqdiag, "seqdiag", "", false, "sequence diagram output")

	flag.UintVarP(&cfg.port_https, "port-https", "", uint(port_https), "port HTTPS")
	flag.StringVarP(&cfg.http_proxy, "http-proxy", "", os.Getenv("http_proxy"), "HTTP proxy")
	flag.StringVarP(&cfg.https_proxy, "https-proxy", "", os.Getenv("https_proxy"), "HTTPS proxy")
	flag.BoolVarP(&cfg.proxy_tunneling, "proxy-tunneling", "", false, "use proxy tunneling (if false just put the proxy to the Host: header)")

	flag.StringVarP(&cfg.cacert, "cacert", "", "", "CA certificate file to sign server and client certificates")
	flag.StringVarP(&cfg.certificate, "cert", "", "", "server certificate PEM file")
	flag.StringVarP(&cfg.key, "key", "", "", "server private key PEM file")

	flag.StringArrayVarP(&cfg.cacerts, "cacerts", "", nil, "additional trusted CA certificate PEM files")
	/*
		fs.StringVarP(&cfg.cakey, "cakey", "", "", "CA certificate private key PEM file")
		fs.BoolVarP(&cfg.mtls, "mtls", "m", false, "set client certificate (same as cert)")
		fs.StringArrayVarP(&cfg.serviceNames, "name", "n", []string{"localhost"}, "the service DNS name(s) for the certificate")
	*/

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of hop:\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	return cfg, flag.Args()
}

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

	if cfg.cacert != "" {
		cfg.cacerts = append(cfg.cacerts, cfg.cacert)
	}
	if len(args) == 1 {
		doHop(cfg, args)
		return
	}

	s := cfg.startHttpServer(quit)
	stls, err := cfg.startHttpsServer(quit)
	if err != nil {
		log.Panicf("failed to start HTTPS server: %v", err)
	}

	switch <-quit {
	case 1:
		log.Info("Shutting down")
		err := s.Shutdown(context.Background())
		if err != nil {
			log.Error("Error:", err)
		}
		<-quit
		if stls != nil {
			err = stls.Shutdown(context.Background())
			if err != nil {
				log.Error("Error:", err)
			}
			<-quit
		}
		if err != nil {
			log.Panic("Failed to stop gracefully")
		}
	case 2:
		log.Panic("Rabbits are coming!")
	}
	log.Info("Exiting normally")
}

func doHop(cfg *config, args []string) {
	u, err := url.Parse(args[len(args)-1])
	if err != nil {
		log.Panic(err)
	}
	params := newReqParams()
	params.tlsInfo = true
	params.showHeaders = true
	req, err := BuildRequest(u, http.MethodGet, params.headers, 0)
	if err != nil {
		log.Error(err)
		return
	}
	client, err := cfg.getClient()
	if err != nil {
		log.Panic(err)
	}
	res, err := client.Do(req)
	if err != nil {
		log.Error(err)
		return
	}
	clog := common.CommandLog{}
	if err := treatResponse(&clog, res, params); err != nil {
		log.Error(err)
	}
	if cfg.seqdiag {
		fmt.Println("= Command output =")
		for _, line := range clog.Output {
			fmt.Println(line)
		}
		fmt.Println("== Response ==")
		if clog.Response != nil {
			if cfg.seqdiag {
				d, _ := seqdiag.Translate(clog.Response)
				fmt.Println(d)
			} else {
				b, err := json.MarshalIndent(clog.Response, "", "  ")
				if err != nil {
					log.Error(err)
				} else {
					fmt.Println(string(b))
				}
			}
		}
	} else {
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		e.Encode(&clog)
	}
}

func (cfg *config) getCert(cn string) *tls.Certificate {
	serverCert, err := tlstools.SignWith(cfg.serviceNames, cn, cfg.cacert, cfg.cakey)
	if err != nil {
		log.Panicf("couldn't sign with provided files: %s", err)
	}
	return serverCert
}
