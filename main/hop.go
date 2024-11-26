package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/0x656b694d/hop/data"
	"github.com/0x656b694d/hop/pkg/seqdiag"
	"github.com/0x656b694d/hop/pkg/tlstools"
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
	verbose         bool
	debug           bool
	static_ca       bool
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

func getConfig() *config {
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

	flag.BoolVarP(&cfg.verbose, "verbose", "v", false, "verbose output")
	flag.BoolVarP(&cfg.debug, "debug", "", false, "debug output")
	flag.BoolVarP(&cfg.static_ca, "static-ca", "", true, "use built-in static CA")
	flag.StringVarP(&cfg.localhost, "interface", "i", "0.0.0.0", "the interface to listen on")
	flag.UintVarP(&cfg.port_http, "port-http", "", uint(port_http), "port HTTP")
	flag.BoolVarP(&cfg.insecure, "insecure", "k", false, "client to skip TLS verification")
	flag.BoolVarP(&cfg.seqdiag, "seqdiag", "", false, "sequence diagram output")

	flag.UintVarP(&cfg.port_https, "port-https", "", uint(port_https), "port HTTPS")
	flag.StringVarP(&cfg.http_proxy, "http-proxy", "", os.Getenv("http_proxy"), "HTTP proxy")
	flag.StringVarP(&cfg.https_proxy, "https-proxy", "", os.Getenv("https_proxy"), "HTTPS proxy")
	flag.BoolVarP(&cfg.proxy_tunneling, "proxy-tunneling", "", false, "use proxy tunneling (if false just put the proxy to the Host: header)")
	flag.StringArrayVarP(&cfg.cacerts, "cacerts", "", nil, "trusted CA certificate PEM files")
	flag.StringVarP(&cfg.cacert, "cacert", "", "", "CA certificate to sign server and client certificates")
	flag.StringVarP(&cfg.cakey, "cakey", "", "", "CA certificate private key PEM file")
	flag.StringVarP(&cfg.certificate, "cert", "", "", "server certificate PEM file")
	flag.StringVarP(&cfg.key, "key", "", "", "server private key PEM file")
	flag.BoolVarP(&cfg.mtls, "mtls", "m", false, "set client certificate (same as cert)")
	flag.StringArrayVarP(&cfg.serviceNames, "name", "n", []string{"localhost"}, "the service DNS name(s) for the certificate")

	flag.Parse()
	return cfg
}

func main() {

	cfg := getConfig()

	if cfg.verbose {
		log.SetLevel(log.InfoLevel)
	}
	if cfg.debug {
		log.SetLevel(log.TraceLevel)
	}
	tlstools.Init(cfg.static_ca)

	var err error
	if len(cfg.https_proxy) != 0 {
		https_proxy_url, err = url.Parse(cfg.https_proxy)
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
	var p *x509.CertPool
	p, err = tlstools.GetCertPool(cfg.cacerts)
	if err != nil {
		log.Panic(err)
	}

	client, err := cfg.getClient(p)
	if err != nil {
		log.Panic(err)
	}

	if flag.NArg() == 1 {
		u, err := url.Parse(flag.Arg(0))
		if err != nil {
			log.Panic(err)
		}
		params := newReqParams()
		params.tlsInfo = true
		params.showHeaders = true
		if req, err := BuildRequest(u, http.MethodGet, params.headers, 0); err != nil {
			log.Error(err)
		} else {
			if res, err := client.Do(req); err != nil {
				log.Error(err)
			} else {
				clog := data.CommandLog{}
				if err := TreatResponse(&clog, res, params, cfg.insecure); err != nil {
					log.Error(err)
				}
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
			}
		}
		return
	}

	hn, _ := os.Hostname()
	slog := &data.ServerLog{
		Server: hn,
		Iface:  cfg.localhost,
		Port:   uint16(cfg.port_http),
		Ports:  uint16(cfg.port_https),
	}

	s := cfg.startHttpServer(client, slog, quit)
	stls, err := cfg.startHttpsServer(client, p, slog, quit)
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

func (cfg *config) getCert(cn string) *tls.Certificate {
	serverCert, err := tlstools.SignWith(cfg.serviceNames, cn, cfg.cacert, cfg.cakey)
	if err != nil {
		log.Panicf("couldn't sign with provided files: %s", err)
	}
	return serverCert
}
