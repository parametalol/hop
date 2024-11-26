package main

import (
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/parametalol/hop/data"
	"github.com/parametalol/hop/pkg/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReq(t *testing.T) {

	def := newReqParams()
	hn, err := os.Hostname()
	assert.NoError(t, err)

	cases := map[string]struct {
		command string

		err      error
		url      string
		code     tools.ResultCode
		skip     bool
		logs     tools.ArrLog
		commands []string

		headers map[string]string
	}{
		"no such command": {command: "-bad command",
			err: errNoSuchCommand, commands: []string{"-bad command"}, logs: tools.ArrLog{},
		},
		"code 500": {command: "-code:500",
			code: 500, commands: []string{"-code:500"}, logs: tools.ArrLog{"Returning code 500"},
		},
		"code no args": {command: "-code",
			err: errMissingArguments, commands: []string{"-code"}, logs: tools.ArrLog{},
		},
		"code abc": {command: "-code:abc",
			err: strconv.ErrSyntax, commands: []string{"-code:abc"}, logs: tools.ArrLog{"Error execuing -code(abc): strconv.Atoi: parsing \"abc\": invalid syntax"},
		},
		"size": {command: "-size:1",
			commands: []string{"-size:1"}, logs: tools.ArrLog{"Will add 1 bytes to the following request"},
		},
		"rsize": {command: "-rsize:1",
			commands: []string{"-rsize:1"}, logs: tools.ArrLog{"Appending 1 bytes", "X", "\n"}},
		"header": {command: "-header:a=b",
			commands: []string{"-header:a=b"}, logs: tools.ArrLog{"Will add header a: b"},
			headers: map[string]string{
				"Accept-Encoding": "text/plain",
				"Content-type":    "text/plain",
				"User-Agent":      "hop",
				"a":               "b",
			},
		},
		"not": {command: "-not/-code:500",
			code: 500, commands: []string{"-not", "-code:500"}, logs: tools.ArrLog{"Returning code 500"}},
		"on": {command: "-on:" + hn + "/-code:500",
			code: 500, commands: []string{"-on:" + hn, "-code:500"}, logs: tools.ArrLog{"Testing host " + hn + " for " + hn, "Returning code 500"}},
		"not on": {command: "-not/-on:" + hn + "/-code:500",
			code: 0, commands: []string{"-not", "-on:" + hn, "-code:500"}, logs: tools.ArrLog{"Testing host " + hn + " for " + hn, "Skipping -code(500)"}},
		"localhost": {command: "localhost%3A12/-code:404",
			commands: []string{}, logs: tools.ArrLog{},
			url: "http://localhost:12/-code:404"},
		"localhost localhost": {command: "localhost%3A12/https%3A%2F%2Flocalhost%3A13/path",
			commands: []string{}, logs: tools.ArrLog{},
			url: "http://localhost:12/https%3A%2F%2Flocalhost%3A13/path"},
	}

	for test, c := range cases {
		t.Run(test, func(t *testing.T) {
			var r data.RequestLog
			u, err := url.Parse("http://testhost/" + c.command)
			assert.NoError(t, err)
			rp, err := makeReq(&r, &http.Request{URL: u})
			if c.err != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, c.err)
				require.Equal(t, (*reqParams)(nil), rp)
			} else {
				require.NoError(t, err)
			}
			if rp != nil {
				if c.url != "" {
					u, _ := url.Parse(c.url)
					assert.Equal(t, u, rp.url)
				} else {
					assert.Equal(t, (*url.URL)(nil), rp.url)

				}
				assert.Equal(t, c.code, rp.code)
			}
			output := tools.ArrLog{}
			commands := []string{}
			for _, c := range r.Process {
				commands = append(commands, c.Command)
				output = append(output, c.Output...)
			}
			assert.Equal(t, c.commands, commands)
			assert.Equal(t, c.logs, output)

			if c.headers != nil {
				require.NotNil(t, rp)
				assert.Equal(t, c.headers, rp.headers)
			} else if rp != nil {
				assert.Equal(t, def.headers, rp.headers)
			}

		})
	}
}

func TestSkipStep(t *testing.T) {
	rp := newReqParams()
	var r tools.ArrLog

	ctx := &cmdContext{skip: true}
	err := step(ctx, &r, &http.Request{}, rp, "-code", "500")
	assert.NoError(t, err)
	assert.Equal(t, 0, int(rp.code))
	assert.Equal(t, "Skipping -code(500)", strings.Join(r, "\n"))
	assert.Equal(t, false, ctx.skip)
}
