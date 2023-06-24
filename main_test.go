package main

import (
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"gotest.tools/assert"
)

func TestReq(t *testing.T) {

	def := newReqParams()
	hn, err := os.Hostname()
	assert.NilError(t, err)

	cases := map[string]struct {
		command string

		err  error
		url  string
		code resultCode
		skip bool
		logs string

		headers map[string]string
	}{
		"no such command": {command: "-bad command",
			err: errNoSuchCommand,
		},
		"code 500": {command: "-code:500",
			code: 500, logs: "Running -code:500\nReturning code 500",
		},
		"code no args": {command: "-code",
			err: errMissingArguments,
		},
		"code abc": {command: "-code:abc",
			err: &strconv.NumError{},
		},
		"size": {command: "-size:1",
			logs: "Running -size:1\nWill add 1 bytes to the following request",
		},
		"rsize": {command: "-rsize:1",
			logs: "Running -rsize:1\nAppending 1 bytes\nX\n\n"},
		"header": {command: "-header:a=b",
			logs: "Running -header:a=b\nWill add header a: b",
			headers: map[string]string{
				"Accept-Encoding": "text/plain",
				"Content-type":    "text/plain",
				"a":               "b",
			},
		},
		"not": {command: "-not/-code:500",
			code: 500, logs: "Running -not\nRunning -code:500\nReturning code 500"},
		"on": {command: "-on:" + hn + "/-code:500",
			code: 500, logs: "Running -on:" + hn + "\nTesting host " + hn + " for " + hn + "\nRunning -code:500\nReturning code 500"},
		"not on": {command: "-not/-on:" + hn + "/-code:500",
			code: 0, logs: "Running -not\nRunning -on:" + hn + "\nTesting host " + hn + " for " + hn + "\nRunning -code:500\nSkipping -code(500)"},
		"localhost": {command: "localhost%3A12/-code:404",
			url: "http://localhost:12/-code:404"},
		"localhost localhost": {command: "localhost%3A12/https%3A%2F%2Flocalhost%3A13/path",
			url: "http://localhost:12/https%3A%2F%2Flocalhost%3A13/path"},
	}

	for test, c := range cases {
		t.Run(test, func(t *testing.T) {
			var r reqLog
			u, err := url.Parse("http://testhost/" + c.command)
			assert.NilError(t, err)
			rp, err := makeReq(&r, &http.Request{URL: u})
			if c.err != nil {
				assert.ErrorType(t, c.err, err)
				assert.Equal(t, (*reqParams)(nil), rp)
				return
			} else {
				assert.NilError(t, err)
			}
			if rp != nil {
				if c.url != "" {
					u, _ := url.Parse(c.url)
					assert.DeepEqual(t, u, rp.url)
				} else {
					assert.Equal(t, (*url.URL)(nil), rp.url)

				}
				assert.Equal(t, c.code, rp.code)
			} else {
				assert.Equal(t, (*reqParams)(nil), rp)
			}
			assert.Equal(t, c.logs, strings.Join(r, "\n"))
			if c.headers != nil {
				assert.DeepEqual(t, c.headers, rp.headers)
			} else {
				assert.DeepEqual(t, def.headers, rp.headers)
			}
		})
	}
}

func TestSkipStep(t *testing.T) {
	rp := newReqParams()
	var r reqLog

	ctx := &cmdContext{skip: true}
	err := step(ctx, &r, &http.Request{}, rp, "-code", "500")
	assert.NilError(t, err)
	assert.Equal(t, 0, int(rp.code))
	assert.Equal(t, "Skipping -code(500)", strings.Join(r, "\n"))
	assert.Equal(t, false, ctx.skip)
}
