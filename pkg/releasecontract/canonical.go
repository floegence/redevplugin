package releasecontract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"unicode/utf8"
)

const (
	maxDocumentBytes = 1024 * 1024
	maxJSONDepth     = 64
	maxJSONNodes     = 100_000
	signingPrefix    = "REDEVPLUGIN-SIGNING-V1\x00"
)

var (
	ErrInvalidDocument  = errors.New("release contract document is invalid")
	ErrInvalidSignature = errors.New("release contract signature is invalid")
	ErrVerifierRequired = errors.New("release contract signature verifier is required")
	ErrUnsupportedUsage = errors.New("release contract signing usage is unsupported")
)

func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: encode canonical value", ErrInvalidDocument)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, fmt.Errorf("%w: decode canonical value", ErrInvalidDocument)
	}
	out := make([]byte, 0, len(raw))
	out, err = appendCanonicalJSON(out, decoded, 0)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func CanonicalSigningLedgerEvidence(evidence SigningLedgerEvidenceV1) ([]byte, error) {
	if err := validateSigningLedgerEvidence(evidence); err != nil {
		return nil, err
	}
	return canonicalJSON(evidence)
}

func appendCanonicalJSON(out []byte, value any, depth int) ([]byte, error) {
	if depth > maxJSONDepth {
		return nil, fmt.Errorf("%w: JSON nesting limit exceeded", ErrInvalidDocument)
	}
	switch typed := value.(type) {
	case nil:
		return append(out, "null"...), nil
	case bool:
		if typed {
			return append(out, "true"...), nil
		}
		return append(out, "false"...), nil
	case string:
		return appendCanonicalJSONString(out, typed)
	case json.Number:
		if !canonicalUnsignedDecimalPattern.MatchString(string(typed)) {
			return nil, fmt.Errorf("%w: non-canonical JSON number", ErrInvalidDocument)
		}
		return append(out, string(typed)...), nil
	case []any:
		out = append(out, '[')
		for index, item := range typed {
			if index > 0 {
				out = append(out, ',')
			}
			var err error
			out, err = appendCanonicalJSON(out, item, depth+1)
			if err != nil {
				return nil, err
			}
		}
		return append(out, ']'), nil
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out = append(out, '{')
		for index, key := range keys {
			if index > 0 {
				out = append(out, ',')
			}
			var err error
			out, err = appendCanonicalJSONString(out, key)
			if err != nil {
				return nil, err
			}
			out = append(out, ':')
			out, err = appendCanonicalJSON(out, typed[key], depth+1)
			if err != nil {
				return nil, err
			}
		}
		return append(out, '}'), nil
	default:
		return nil, fmt.Errorf("%w: unsupported canonical JSON value", ErrInvalidDocument)
	}
}

func appendCanonicalJSONString(out []byte, value string) ([]byte, error) {
	if !utf8.ValidString(value) {
		return nil, fmt.Errorf("%w: JSON string is not valid UTF-8", ErrInvalidDocument)
	}
	out = append(out, '"')
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		value = value[size:]
		switch r {
		case '"', '\\':
			out = append(out, '\\', byte(r))
		case '\b':
			out = append(out, `\b`...)
		case '\f':
			out = append(out, `\f`...)
		case '\n':
			out = append(out, `\n`...)
		case '\r':
			out = append(out, `\r`...)
		case '\t':
			out = append(out, `\t`...)
		default:
			if r < 0x20 {
				out = append(out, `\u00`...)
				const hex = "0123456789abcdef"
				out = append(out, hex[byte(r)>>4], hex[byte(r)&0x0f])
				continue
			}
			out = utf8.AppendRune(out, r)
		}
	}
	return append(out, '"'), nil
}

func signingPreimage(usage SigningUsage, value any) ([]byte, error) {
	if !validSigningUsage(usage) {
		return nil, ErrUnsupportedUsage
	}
	payload, err := canonicalJSON(value)
	if err != nil {
		return nil, err
	}
	preimage := make([]byte, 0, len(signingPrefix)+len(usage)+1+len(payload))
	preimage = append(preimage, signingPrefix...)
	preimage = append(preimage, usage...)
	preimage = append(preimage, 0)
	preimage = append(preimage, payload...)
	return preimage, nil
}

func validSigningUsage(usage SigningUsage) bool {
	switch usage {
	case SigningUsageRootDelegation,
		SigningUsagePackage,
		SigningUsageReleaseMetadata,
		SigningUsageSourcePolicy,
		SigningUsageSourcePolicyPointer,
		SigningUsageRevocation,
		SigningUsageRevocationPointer:
		return true
	default:
		return false
	}
}

func decodeCanonicalDocument(raw []byte, value any, validate func() error) error {
	if len(raw) == 0 || len(raw) > maxDocumentBytes || !utf8.Valid(raw) {
		return fmt.Errorf("%w: document size or encoding", ErrInvalidDocument)
	}
	if err := validateJSONStructure(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("%w: closed JSON decode", ErrInvalidDocument)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing JSON value", ErrInvalidDocument)
	}
	if err := validate(); err != nil {
		return err
	}
	canonical, err := canonicalJSON(value)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, canonical) {
		return fmt.Errorf("%w: document is not canonical JSON", ErrInvalidDocument)
	}
	return nil
}

func validateJSONStructure(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	nodes := 0
	if err := consumeJSONValue(decoder, 0, &nodes); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			_ = token
		}
		return fmt.Errorf("%w: trailing JSON value", ErrInvalidDocument)
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, depth int, nodes *int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("%w: JSON nesting limit exceeded", ErrInvalidDocument)
	}
	*nodes++
	if *nodes > maxJSONNodes {
		return fmt.Errorf("%w: JSON node limit exceeded", ErrInvalidDocument)
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%w: malformed JSON", ErrInvalidDocument)
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("%w: malformed JSON object", ErrInvalidDocument)
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("%w: malformed JSON object key", ErrInvalidDocument)
			}
			if _, exists := keys[key]; exists {
				return fmt.Errorf("%w: duplicate JSON field", ErrInvalidDocument)
			}
			keys[key] = struct{}{}
			if err := consumeJSONValue(decoder, depth+1, nodes); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return fmt.Errorf("%w: malformed JSON object", ErrInvalidDocument)
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder, depth+1, nodes); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return fmt.Errorf("%w: malformed JSON array", ErrInvalidDocument)
		}
	default:
		return fmt.Errorf("%w: malformed JSON delimiter", ErrInvalidDocument)
	}
	return nil
}
