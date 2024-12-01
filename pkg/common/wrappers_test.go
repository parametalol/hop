package common

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

type test struct {
	String string
	Number int
	Ptr    *struct {
		InnerString string
	}
	Bool bool
	Err  Error
}

type testWrap test

func (e *testWrap) MarshalJSON() ([]byte, error) {
	return omitEmpty(e)
}

func Test_marhalJson(t *testing.T) {
	t.Run("test original", func(t *testing.T) {
		obj := &test{}
		data, err := json.Marshal(obj)
		assert.NoError(t, err)
		assert.Equal(t, `{"String":"","Number":0,"Ptr":null,"Bool":false,"Err":null}`, string(data))
	})
	t.Run("test empty", func(t *testing.T) {
		obj := &test{}
		data, err := omitEmpty((*testWrap)(obj))
		assert.NoError(t, err)
		assert.Equal(t, "{}", string(data))
	})
	t.Run("test non-empty", func(t *testing.T) {
		obj := &test{
			String: "string value",
			Number: 15,
			Ptr: &struct{ InnerString string }{
				InnerString: "inner value",
			},
			Bool: true,
			Err:  &ErrorWrapper{errors.New("oops")},
		}
		data, err := omitEmpty((*testWrap)(obj))
		assert.NoError(t, err)
		assert.Equal(t, `{"Bool":true,"Err":"oops","Number":15,"Ptr":{"InnerString":"inner value"},"String":"string value"}`, string(data))
	})
	t.Run("test json.Marshal", func(t *testing.T) {
		obj := &test{}
		data, err := json.Marshal((*testWrap)(obj))
		assert.NoError(t, err)
		assert.Equal(t, `{}`, string(data))
	})
}
