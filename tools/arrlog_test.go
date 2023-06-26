package tools

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func addToR(r *ArrLog, msg string) {
	r.Appendln(msg)
}

func TestArrLog_Append(t *testing.T) {
	var r ArrLog

	assert.Len(t, r, 0)
	r.Appendln("abc", "xyz")
	assert.Len(t, r, 1)
	assert.Equal(t, "abc\nxyz", r[0])
	addToR(&r, "def")
	assert.Len(t, r, 2)
	assert.Equal(t, "def", r[1])

	r = ArrLog{}
	r.Appendf("-%s-", "abc")
	assert.Len(t, r, 1)
	assert.Equal(t, "-abc-", r[0])
}
