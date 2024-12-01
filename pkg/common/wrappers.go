package common

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"reflect"
)

func isEmptyValue(v reflect.Value) bool {
	if v.Kind() == reflect.Pointer {
		return v.IsNil()
	}
	return v.IsZero()
}

// omitEmpty doesn't read the tags of the obj own fields.
func omitEmpty[T any](obj *T) ([]byte, error) {
	result := make(map[string]interface{})

	v := reflect.Indirect(reflect.ValueOf(obj))
	typeOfOriginal := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if !field.IsValid() {
			continue
		}
		if !isEmptyValue(field) {
			fieldName := typeOfOriginal.Field(i).Name
			result[fieldName] = field.Interface()
		}
	}
	return json.Marshal(result)
}

type Certificate x509.Certificate

func (e *Certificate) MarshalJSON() ([]byte, error) {
	return omitEmpty(e)
}

type ConnectionState tls.ConnectionState

func (e *ConnectionState) MarshalJSON() ([]byte, error) {
	return omitEmpty(e)
}

type ErrorWrapper struct{ Err error }
type Error = *ErrorWrapper

func (e *ErrorWrapper) MarshalJSON() ([]byte, error) {
	if e == nil || e.Err == nil {
		return json.Marshal(nil)
	}
	return json.Marshal(e.Err.Error())
}
