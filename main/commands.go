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

	"github.com/parametalol/hop/pkg/common"
	"github.com/parametalol/hop/pkg/tlstools"
	"github.com/parametalol/hop/pkg/tools"
)

type cmdContext struct {
	skip, not bool
}

func makeReq(rlog *common.RequestLog, req *http.Request) (*reqParams, error) {

	nextCommand, path, err := tools.GetFirstCommand(req.URL)
	if err != nil {
		return nil, err
	}

	rp := newReqParams()
	ctx := &cmdContext{}
	for strings.HasPrefix(nextCommand, "-") {
		clog := &common.CommandLog{
			Command: nextCommand,
		}
		rlog.Process = append(rlog.Process, clog)
		r := &clog.Output
		cmd, args := tools.SplitCommandArgs(nextCommand)
		if err := checkCommand(args, cmd); err != nil {
			return nil, err
		}
		if err := step(ctx, r, req, rp, cmd, args); err != nil {
			r.Appendf("Error execuing %s(%s): %v", cmd, args, err)
			return nil, err
		}
		nextCommand, path = tools.Pop(path)
	}
	if nextCommand != "" {
		if ctx.skip {
			// r.appendf("Skipping call to %s", nextCommand)
			return nil, nil
		}
		var err error
		if rp.url, err = tools.BuildURL(nextCommand, path); err != nil {
			return nil, err
		}
	}
	return rp, nil
}

func q(c int) {
	quit <- c
}

func step(ctx *cmdContext, r *tools.ArrLog, req *http.Request, rp *reqParams, command, args string) error {

	if ctx.skip {
		r.Appendf("Skipping %s(%s)", command, args)
		ctx.skip = false
		return nil
	}
	switch command {
	case "-help":
		for k, v := range help {
			r.Appendf("%-13s - %s", strings.Join([]string{k, v[0]}, ":"), v[1])
		}
		r.Appendln("Examples:",
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
		r.Appendf("Waited for %d ms", d)
	case "-info":
		rp.showHeaders = true
		dump, err := httputil.DumpRequest(req, req.ContentLength < 1024)
		if err == nil {
			for _, line := range strings.Split(string(dump), "\r\n") {
				r.Appendf("%s", line)
			}
		} else {
			r.Appendf("Error: %s", err)
		}
	case "-method":
		rp.method = args
	case "-rtrip":
		rp.rtrip = true
	case "-tls":
		rp.tlsInfo = true
		r.Append("Server request TLS info:")
		tlstools.AppendTLSInfo(r, req.TLS, false)
	case "-header", "-rheader":
		hv := strings.SplitN(args, "=", 2)
		if len(hv) != 2 {
			return fmt.Errorf("missing header value")
		}
		value, err := url.PathUnescape(hv[1])
		if err != nil {
			return fmt.Errorf("bad value for header (%s: %s): %w", hv[0], hv[1], err)
		}
		r.Appendf("Will add header %s: %s", hv[0], value)
		if command == "-header" {
			rp.headers[hv[0]] = value
		} else {
			rp.rheaders[hv[0]] = value
		}
	case "-fheader":
		r.Appendf("Will forward header %s: %s", args, req.Header.Get(args))
		rp.headers[args] = req.Header.Get(args)
		rp.fheaders = append(rp.fheaders, args)
	case "-code":
		c, err := strconv.Atoi(args)
		if err != nil {
			return err
		}
		rp.code.Set(c)
		r.Appendf("Returning code %d", rp.code)
	case "-rsize":
		b, err := strconv.Atoi(args)
		if err != nil {
			return err
		}
		r.Appendf("Appending %d bytes", b)
		r.Appendln(strings.Repeat("X", b))
		r.Appendln("\n")
	case "-env":
		r.Appendf("%s=%s", args, os.Getenv(args))
	case "-size":
		b, err := strconv.Atoi(args)
		if err != nil {
			return err
		}
		rp.size = b
		r.Appendf("Will add %d bytes to the following request", rp.size)
	case "-not":
		ctx.not = !ctx.not
	case "-on":
		value, err := url.PathUnescape(args)
		if err != nil {
			return err
		}
		hn, err := os.Hostname()
		if err != nil {
			r.Appendf("Cannot retrieve hostname %s: %v", command, err)
			ctx.skip = true
		} else {
			r.Appendf("Testing host %s for %s", hn, value)
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
		r.Appendln("Quitting")
		defer q(1)
	case "-crash":
		defer q(2)
	}
	return nil
}
