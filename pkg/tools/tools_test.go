package tools

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCode(t *testing.T) {
	var c ResultCode

	assert.Equal(t, 0, int(c))
	c.Set(5)
	assert.Equal(t, 5, int(c))
	c.Set(6)
	assert.Equal(t, 5, int(c))
}

func TestPop(t *testing.T) {
	command, path := Pop("abc/def/xyz")
	assert.Equal(t, "abc", command)
	assert.Equal(t, "def/xyz", path)

	command, path = Pop(path)
	assert.Equal(t, "def", command)
	assert.Equal(t, "xyz", path)

	command, path = Pop(path)
	assert.Equal(t, "xyz", command)
	assert.Equal(t, "", path)

	command, path = Pop(path)
	assert.Equal(t, "", command)
	assert.Equal(t, "", path)
}

func TestSplitCommandArgs(t *testing.T) {
	cases := map[string]struct {
		input         string
		command, args string
	}{
		"-a":       {"-a", "-a", ""},
		"-a:b":     {"-a:b", "-a", "b"},
		"-abc":     {"-abc", "-abc", ""},
		"-abc:def": {"-abc:def", "-abc", "def"},
	}
	for test, c := range cases {
		t.Run(test, func(t *testing.T) {
			command, args := SplitCommandArgs(c.input)
			assert.Equal(t, c.command, command)
			assert.Equal(t, c.args, args)
		})
	}
}

func TestGetFirstCommand(t *testing.T) {
	cases := map[string]struct {
		url         string
		first, next string
	}{
		"abs":               {"https://localhost:12/-first/next", "-first", "next"},
		"rel":               {"/first/next", "first/", "next"},
		"rel command":       {"/-first/next", "-first", "next"},
		"abs google":        {"https://localhost:12/http%3a%2f%2fgoogle.com/whoami", "http://google.com/", "whoami"},
		"abs google nonesc": {"https://localhost:12/http://google.com/whoami", "http:/", "/google.com/whoami"},
		"abs google google": {"https://localhost:12/http%3a%2f%2fgoogle.com/http%3a%2f%2fgoogle.com/next", "http://google.com/", "http%3a%2f%2fgoogle.com/next"},
		"info google":       {"https://localhost:12/-info/http%3a%2f%2fgoogle.com/whoami", "-info", "http%3a%2f%2fgoogle.com/whoami"},
	}
	for test, c := range cases {
		t.Run(test, func(t *testing.T) {
			u, err := url.Parse(c.url)
			assert.NoError(t, err)
			f, n, err := GetFirstCommand(u)
			assert.NoError(t, err)
			assert.Equal(t, c.first, f)
			assert.Equal(t, c.next, n)
		})
	}
}

func TestBuildURL(t *testing.T) {
	cases := []struct{ addr, path, exp string }{
		{"http%3a%2f%2fgoogle.com", "whoami", "http://google.com/whoami"},
		{"http%3a%2f%2fgoogle.com/", "whoami", "http://google.com/whoami"},
		{"http%3a%2f%2fgoogle.com/", "-whoami", "http://google.com/-whoami"},
		{"http%3a%2f%2fgoogle.com", "-whoami", "http://google.com/-whoami"},
		{"google.com", "-whoami", "http://google.com/-whoami"},
		{"google.com", "", "http://google.com/"},
		{"", "", "http://"},
	}
	for _, c := range cases {
		t.Run(c.exp, func(t *testing.T) {
			u, err := BuildURL(c.addr, c.path)
			assert.NoError(t, err)
			exp, _ := url.Parse(c.exp)
			assert.Equal(t, exp, u)
		})
	}
}
