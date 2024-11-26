package tools

import (
	"fmt"
	"net/url"
	"strings"
)

type ResultCode int

func (c *ResultCode) Set(v int) int {
	if *c == 0 {
		*c = ResultCode(v)
	}
	return int(*c)
}

func Pop(path string) (string, string) {
	parts := strings.SplitN(path, "/", 2)
	if len(parts) > 1 {
		path = parts[1]
	} else {
		path = ""
	}
	return parts[0], path
}

func SplitCommandArgs(c string) (string, string) {
	cmd := strings.SplitN(c, ":", 2)
	args := ""
	if len(cmd) > 1 {
		args = cmd[1]
	}
	return cmd[0], args
}

func GetFirstCommand(u *url.URL) (first string, next string, err error) {
	first = u.EscapedPath()
	parts := strings.SplitN(first, "/", 3) // drop leading slash
	if len(parts) > 1 {
		first, err = url.PathUnescape(parts[1])
		if err != nil {
			return "", "", err
		}
		if first != "" && first[0] != '-' {
			first += "/"
		}
	}
	if len(parts) > 2 {
		next = parts[2]
	}
	return
}

func BuildURL(addr, path string) (*url.URL, error) {
	addr, err := url.PathUnescape(addr)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		addr = "http://" + addr
	}
	if addr[len(addr)-1] != '/' {
		addr += "/"
	}
	u, err := url.Parse(fmt.Sprintf("%s%s", addr, path))
	if err != nil {
		return nil, fmt.Errorf("cannot call %s: %s", addr, err.Error())
	}
	return u, nil
}
