package releasetrust

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
)

func decodeClosedJSON(raw []byte, target any, maxBytes int, invalid error) error {
	if len(raw) == 0 || len(raw) > maxBytes || !json.Valid(raw) || hasJSONByteOrderMark(raw) {
		return invalid
	}
	if err := rejectDuplicateFields(raw, invalid); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return invalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return invalid
	}
	return nil
}

func rejectDuplicateFields(raw []byte, invalid error) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return invalid
				}
				if _, exists := seen[key]; exists {
					return invalid
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
				return invalid
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			if closing, err := decoder.Token(); err != nil || closing != json.Delim(']') {
				return invalid
			}
		default:
			return invalid
		}
		return nil
	}
	if err := walk(); err != nil {
		return invalid
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return invalid
	}
	return nil
}

func hasJSONByteOrderMark(raw []byte) bool {
	return len(raw) >= 3 && raw[0] == 0xef && raw[1] == 0xbb && raw[2] == 0xbf
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
