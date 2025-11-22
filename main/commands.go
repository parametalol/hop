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
	"github.com/parametalol/hop/pkg/tools"
)

var help = map[string][2]string{
	"-code":    {"N", "respond with HTTP code N"},
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
	"-rheader": {"H=V", "add header H: V to the response"},
	"-rnd":     {"P", "execute next command with P% probability"},
	"-rsize":   {"B", "add B bytes of payload to the response"},
	"-size":    {"B", "add B bytes of payload to the following query"},
	"-wait":    {"T", "wait for T ms before response"},
	"-env":     {"V", "return the value of an environment variable"},
}

type cmdContext struct {
	skip, not bool
}

func makeCommandLog(command, args string) *common.CommandLog {
	if args != "" {
		command += ":" + args
	}
	return &common.CommandLog{
		Command: command,
	}
}

func execCommand(ctx *cmdContext, req *http.Request, rp *reqParams, cmd string) *common.CommandLog {
	cmd, args := tools.SplitCommandArgs(cmd)
	if err := checkCommand(cmd, args); err != nil {
		clog := makeCommandLog(cmd, args)
		clog.Err(err)
		clog.Code = 400
		return clog
	}
	return step(ctx, req, rp, cmd, args)
}

func q(c int) {
	quit <- c
}

func step(ctx *cmdContext, req *http.Request, rp *reqParams, command, args string) *common.CommandLog {
	result := makeCommandLog(command, args)
	o := &result.Output
	if ctx.skip {
		o.Appendf("Skipping %s(%s)", command, args)
		ctx.skip = false
		return result
	}

	switch command {
	case "-help":
		for k, v := range help {
			o.Appendf("%-13s - %s", strings.Join([]string{k, v[0]}, ":"), v[1])
		}
		o.Appendln("Examples:",
			"curl -H \"a: b\" hop1/-info",
			"\tthis will call hop1 which will show some details of the request",
			"curl -H \"a: b\" hop1/-fheader:a/hop2",
			"\tthis will call hop1 which will call hop2 with forwarded header A",
			"curl hop1/-rnd:50/hop2/hop3/-on:hop2/-code:500",
			"\tthis will call hop1 which will call hop2 or hop3 (50%). hop2 would call hop3 and return error code 500")
	case "-wait":
		d, err := strconv.Atoi(args)
		if err != nil {
			return result.Err(err)
		}
		time.Sleep(time.Duration(d) * time.Millisecond)
		o.Appendf("Waited for %d ms", d)
	case "-info":
		rp.showHeaders = true
		if req != nil {
			dump, err := httputil.DumpRequest(req, req.ContentLength < 1024)
			if err == nil {
				for _, line := range strings.Split(string(dump), "\r\n") {
					o.Appendf("%s", line)
				}
			} else {
				o.Appendf("Error: %s", err)
			}
		}
	case "-method":
		rp.method = args
	case "-rtrip":
		rp.rtrip = true
	case "-tls":
		rp.tlsInfo = true
		// o.Append("Server request TLS info:")
		// tlstools.AppendTLSInfo(o, req.TLS, false)
	case "-header", "-rheader":
		hv := strings.SplitN(args, "=", 2)
		if len(hv) != 2 {
			return result.Err(fmt.Errorf("missing header value"))
		}
		value, err := url.PathUnescape(hv[1])
		if err != nil {
			return result.Err(fmt.Errorf("bad value for header (%s: %s): %w", hv[0], hv[1], err))
		}
		o.Appendf("Will add header %s: %s", hv[0], value)
		if command == "-header" {
			rp.headers[hv[0]] = value
		} else {
			rp.rheaders[hv[0]] = value
		}
	case "-fheader":
		if req == nil {
			break
		}
		o.Appendf("Will forward header %s: %s", args, req.Header.Get(args))
		rp.headers[args] = req.Header.Get(args)
		rp.fheaders = append(rp.fheaders, args)
	case "-code":
		c, err := strconv.Atoi(args)
		if err != nil {
			return result.Err(err)
		}
		rp.code.Set(c)
		o.Appendf("Returning code %d", rp.code)
	case "-rsize":
		b, err := strconv.Atoi(args)
		if err != nil {
			return result.Err(err)
		}
		o.Appendf("Appending %d bytes", b)
		o.Appendln(strings.Repeat("X", b))
		o.Appendln("\n")
	case "-env":
		o.Appendf("%s=%s", args, os.Getenv(args))
	case "-size":
		b, err := strconv.Atoi(args)
		if err != nil {
			return result.Err(err)
		}
		rp.size = b
		o.Appendf("Will add %d bytes to the following request", rp.size)
	case "-not":
		ctx.not = !ctx.not
	case "-on":
		value, err := url.PathUnescape(args)
		if err != nil {
			return result.Err(err)
		}
		hn, err := os.Hostname()
		if err != nil {
			o.Appendf("Cannot retrieve hostname %s: %v", command, err)
			ctx.skip = true
		} else {
			o.Appendf("Testing host %s for %s", hn, value)
			ctx.skip = !strings.Contains(hn, value)
			if ctx.not {
				ctx.skip = !ctx.skip
				ctx.not = false
			}
		}
	case "-if":
		if req == nil {
			break
		}
		hv := strings.SplitN(args, "=", 2)
		if len(hv) != 2 {
			return result.Err(wrapErr(fmt.Errorf("missing header value"), command))
		}
		value, err := url.PathUnescape(hv[1])
		if err != nil {
			return result.Err(fmt.Errorf("bad value for header (%s: %s): %w", hv[0], hv[1], err))
		}
		ctx.skip = !(strings.ToLower(hv[0]) == "host" && strings.Contains(req.Host, value)) && !strings.Contains(req.Header.Get(hv[0]), value)
		if ctx.not {
			ctx.skip = !ctx.skip
			ctx.not = false
		}
	case "-rnd":
		p, err := strconv.Atoi(args)
		if err != nil {
			return result.Err(err)
		}
		ctx.skip = p <= rand.Intn(100)
		if ctx.not {
			ctx.skip = !ctx.skip
			ctx.not = false
		}
	case "-quit":
		o.Appendln("Quitting")
		defer q(1)
	case "-crash":
		defer q(2)
	}
	return result
}
