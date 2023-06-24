package main

import (
	"fmt"
	"io"
	"net/url"
	"strings"
)

type reqLog []string

func (l *reqLog) append(s ...string) {
	*l = append(*l, strings.Join(s, "\n"))
}

func (l *reqLog) appendf(f string, args ...any) {
	*l = append(*l, fmt.Sprintf(f, args...))
}

func (l *reqLog) write(w io.Writer) {
	for _, line := range *l {
		io.WriteString(w, "| ")
		io.WriteString(w, line)
		io.WriteString(w, "\n")
	}
}

type resultCode int

func (c *resultCode) set(v int) int {
	if *c == 0 {
		*c = resultCode(v)
	}
	return int(*c)
}

func pop(path string) (string, string) {
	parts := strings.SplitN(path, "/", 2)
	if len(parts) > 1 {
		path = parts[1]
	} else {
		path = ""
	}
	return parts[0], path
}

func splitCommandArgs(c string) (string, string) {
	cmd := strings.SplitN(c, ":", 2)
	args := ""
	if len(cmd) > 1 {
		args = cmd[1]
	}
	return cmd[0], args
}

func getFirstCommand(u *url.URL) (first string, next string, err error) {
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
