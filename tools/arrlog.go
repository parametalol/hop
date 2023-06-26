package tools

import (
	"fmt"
	"strings"
)

type ArrLog []string

func (l *ArrLog) Appendln(s ...string) {
	*l = append(*l, strings.Join(s, "\n"))
}

func (l *ArrLog) Append(s ...string) {
	*l = append(*l, s...)
}

func (l *ArrLog) Appendf(f string, args ...any) {
	*l = append(*l, fmt.Sprintf(f, args...))
}
