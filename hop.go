package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

func buildRequest(url *url.URL, headers *map[string]string, size int) (*http.Request, error) {
	log.Printf("Call %s, sending %d bytes and %v", url, size, *headers)
	payload := bytes.Repeat([]byte{'X'}, size)

	req, err := http.NewRequest("GET", url.String(), bytes.NewReader(payload))
	if err != nil || req == nil {
		return nil, err
	}

	for h, v := range *headers {
		if strings.ToLower(h) == "host" {
			req.Host = v
		} else {
			req.Header.Set(h, v)
		}
	}
	return req, err
}

var (
	// Create a summary to track fictional interservice HOP latencies for three
	// distinct services with different latency distributions. These services are
	// differentiated via a "service" label.
	hopDurations = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "hop_durations_seconds",
			Help:       "HOP latency distributions.",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"service"},
	)
)

type nullWriter struct{}

func (nw nullWriter) Write(p []byte) (n int, err error) {
	return 0, nil
}

type config struct {
	insecure        bool
	verbose         bool
	port_http       uint
	port_https      uint
	port_metrics    uint
	http_proxy      string
	https_proxy     string
	proxy_tunneling bool
	cacert          string
	cakey           string
	certificate     string
	key             string
	localhost       string
	serviceNames    []string
}

func getConfig() *config {
	var port_http uint64 = 80
	var port_https uint64 = 443
	var port_metrics uint64 = 8080
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
	flag.StringVarP(&cfg.localhost, "interface", "i", "0.0.0.0", "the interface to listen on")
	flag.UintVarP(&cfg.port_http, "port-http", "", uint(port_http), "port HTTP")
	flag.UintVarP(&cfg.port_metrics, "port-metrics", "", uint(port_metrics), "port Prometheus metrics")
	flag.BoolVarP(&cfg.insecure, "insecure", "k", false, "client to skip TLS verification")

	flag.UintVarP(&cfg.port_https, "port-https", "", uint(port_https), "port HTTPS")
	flag.StringVarP(&cfg.http_proxy, "http-proxy", "", os.Getenv("http_proxy"), "HTTP proxy")
	flag.StringVarP(&cfg.https_proxy, "https-proxy", "", os.Getenv("https_proxy"), "HTTPS proxy")
	flag.BoolVarP(&cfg.proxy_tunneling, "proxy-tunneling", "", false, "use proxy tunneling (if false just put the proxy to the Host: header)")
	flag.StringVarP(&cfg.cacert, "cacert", "", "", "CA certificate PEM file")
	flag.StringVarP(&cfg.cakey, "cakey", "", "", "CA certificate private key PEM file")
	flag.StringVarP(&cfg.certificate, "cert", "", "", "server certificate PEM file")
	flag.StringVarP(&cfg.key, "key", "", "", "server private key PEM file")
	flag.StringArrayVarP(&cfg.serviceNames, "name", "n", []string{"localhost"}, "the service DNS name(s) for the certificate")

	flag.Parse()
	return cfg
}

func main() {

	cfg := getConfig()

	if cfg.verbose {
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(nullWriter{})
	}
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

	// Register the summary and the histogram with Prometheus's default registry.
	prometheus.MustRegister(hopDurations)

	var p *x509.CertPool
	p, err = getCertPool(cfg.cacert)
	if err != nil {
		log.Panic(err)
	}

	client, err := cfg.getClient(p)
	if err != nil {
		log.Panic(err)
	}
	s := cfg.startHttpServer(client, quit)
	stls, err := cfg.startHttpsServer(client, p, quit)
	if err != nil {
		log.Panicf("failed to start HTTPS server: %v", err)
	}

	metrics := &http.Server{
		Addr:           net.JoinHostPort(cfg.localhost, strconv.FormatUint(uint64(cfg.port_metrics), 10)),
		Handler:        promhttp.Handler(),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
		ErrorLog:       log.New(os.Stdout, "http: ", 0),
	}

	go func() {
		fmt.Println("Serving /metrics on", cfg.localhost, cfg.port_metrics)
		// metrics.Handle("/metrics", promhttp.Handler())
		fmt.Println(metrics.ListenAndServe())
		quit <- 5
	}()

	switch <-quit {
	case 1:
		fmt.Println("Shutting down")
		err := s.Shutdown(context.Background())
		if err != nil {
			fmt.Println("Error:", err)
		}
		<-quit
		if stls != nil {
			err = stls.Shutdown(context.Background())
			if err != nil {
				fmt.Println("Error:", err)
			}
			<-quit
		}
		if err != nil {
			panic("Failed to stop gracefully")
		}
	case 2:
		panic("Rabbits are coming!")
	}
	fmt.Println("Exiting normally")
}
