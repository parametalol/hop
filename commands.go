package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type cmdContext struct {
	skip, not bool
}

func makeReq(r *reqLog, req *http.Request) (*reqParams, error) {

	nextCommand, path, err := getFirstCommand(req.URL)
	if err != nil {
		return nil, err
	}

	rp := newReqParams()
	ctx := &cmdContext{}
	for strings.HasPrefix(nextCommand, "-") {
		cmd, args := splitCommandArgs(nextCommand)
		if err := checkCommand(args, cmd); err != nil {
			return nil, err
		}
		if args != "" {
			r.appendf("Running %s:%s", cmd, args)
		} else {
			r.appendf("Running %s", cmd)
		}

		if err := step(ctx, r, req, rp, cmd, args); err != nil {
			r.appendf("Error execuing %s(%s): %v", cmd, args, err)
			return nil, err
		}
		nextCommand, path = pop(path)
	}
	if nextCommand != "" {
		if ctx.skip {
			r.appendf("Skipping call to %s", nextCommand)
			return nil, nil
		}
		var err error
		if rp.url, err = buildURL(nextCommand, path); err != nil {
			return nil, err
		}
	}
	return rp, nil
}

func q(c int) {
	quit <- c
}

func step(ctx *cmdContext, r *reqLog, req *http.Request, rp *reqParams, command, args string) error {

	if ctx.skip {
		r.appendf("Skipping %s(%s)", command, args)
		ctx.skip = false
		return nil
	}
	switch command {
	case "-help":
		for k, v := range help {
			r.appendf("%-13s - %s", strings.Join([]string{k, v[0]}, ":"), v[1])
		}
		r.appendln("Examples:",
			"curl -H \"a: b\" hop1/-info",
			"\tthis will call hop1 which will show some details of the request",
			"curl -H \"a: b\" hop1/-fheader:a/hop2",
			"\tthis will call hop1 which will call hop2 with forwarded header A",
			"curl hop1/-rnd:50/hop2/hop3/-on:hop2/-code:500",
			"\tthis will call hop1 which will call hop2 or hop3 (50%). hop2 would call hop3 and return error code 500")
	case "-wait":
		d, err := strconv.Atoi(args)
		if err != nil {
			return err
		}
		time.Sleep(time.Duration(d) * time.Millisecond)
		r.appendf("Waited for %d ms", d)
	case "-info":
		rp.showHeaders = true
		dump, err := httputil.DumpRequest(req, req.ContentLength < 1024)
		if err == nil {
			for _, line := range strings.Split(string(dump), "\n") {
				r.appendf(".\t%s", line)
			}
		} else {
			r.appendf("Error: %s", err)
		}
	case "-tls":
		rp.tlsInfo = !ctx.not
		if ctx.not {
			ctx.not = false
			break
		}
		appendTLSInfo(r, req.TLS, "server")
	case "-header", "-rheader":
		hv := strings.SplitN(args, "=", 2)
		if len(hv) != 2 {
			return fmt.Errorf("missing header value")
		}
		value, err := url.PathUnescape(hv[1])
		if err != nil {
			return fmt.Errorf("bad value for header (%s: %s): %w", hv[0], hv[1], err)
		}
		r.appendf("Will add header %s: %s", hv[0], value)
		if command == "-header" {
			rp.headers[hv[0]] = value
		} else {
			rp.rheaders[hv[0]] = value
		}
	case "-fheader":
		r.appendf("Will forward header %s: %s", args, req.Header.Get(args))
		rp.headers[args] = req.Header.Get(args)
		rp.fheaders = append(rp.fheaders, args)
	case "-code":
		c, err := strconv.Atoi(args)
		if err != nil {
			return err
		}
		rp.code.set(c)
		r.appendf("Returning code %d", rp.code)
	case "-rsize":
		b, err := strconv.Atoi(args)
		if err != nil {
			return err
		}
		r.appendf("Appending %d bytes", b)
		r.appendln(strings.Repeat("X", b))
		r.appendln("\n")
	case "-env":
		r.appendf("%s=%s", args, os.Getenv(args))
	case "-size":
		b, err := strconv.Atoi(args)
		if err != nil {
			return err
		}
		rp.size = b
		r.appendf("Will add %d bytes to the following request", rp.size)
	case "-not":
		ctx.not = !ctx.not
	case "-on":
		value, err := url.PathUnescape(args)
		if err != nil {
			return err
		}
		hn, err := os.Hostname()
		if err != nil {
			r.appendf("Cannot retrieve hostname %s: %v", command, err)
			ctx.skip = true
		} else {
			r.appendf("Testing host %s for %s", hn, value)
			ctx.skip = !strings.Contains(hn, value)
			if ctx.not {
				ctx.skip = !ctx.skip
				ctx.not = false
			}
		}
	case "-if":
		hv := strings.SplitN(args, "=", 2)
		if len(hv) != 2 {
			return wrapErr(fmt.Errorf("missing header value"), command)
		}
		value, err := url.PathUnescape(hv[1])
		if err != nil {
			return fmt.Errorf("bad value for header (%s: %s): %w", hv[0], hv[1], err)
		}
		ctx.skip = !(strings.ToLower(hv[0]) == "host" && strings.Contains(req.Host, value)) && !strings.Contains(req.Header.Get(hv[0]), value)
		if ctx.not {
			ctx.skip = !ctx.skip
			ctx.not = false
		}
	case "-rnd":
		p, err := strconv.Atoi(args)
		if err != nil {
			return err
		}
		ctx.skip = p <= rand.Intn(100)
		if ctx.not {
			ctx.skip = !ctx.skip
			ctx.not = false
		}
	case "-quit":
		r.appendln("Quitting")
		defer q(1)
	case "-crash":
		defer q(2)
	}
	return nil
}
