package jsonvalue

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxEncodedBytes = 512 * 1024
	maxDepth        = 64
	maxNodes        = 32768
	maxSafeInteger  = int64(1<<53 - 1)
)

var (
	errInvalidValue   = errors.New("invalid JSON value")
	jsonMarshalerType = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	textMarshalerType = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
	jsonNumberType    = reflect.TypeOf(json.Number(""))
)

type decoderState struct {
	decoder *json.Decoder
	nodes   int
}

type nativeVisit struct {
	typeName reflect.Type
	pointer  uintptr
	length   int
	capacity int
}

type nativeState struct {
	nodes       int
	approxBytes int
	active      map[nativeVisit]struct{}
}

type canonicalState struct {
	nodes int
	bytes int
}

func Normalize(value any) (normalized any, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			normalized = nil
			err = fmt.Errorf("%w: normalization panic", errInvalidValue)
		}
	}()
	if err := validateNativeStructure(value); err != nil {
		return nil, err
	}

	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidValue, err)
	}
	if len(raw) > maxEncodedBytes {
		return nil, fmt.Errorf("%w: encoded value exceeds %d bytes", errInvalidValue, maxEncodedBytes)
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	state := decoderState{decoder: decoder}
	normalized, err = state.readValue(0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errInvalidValue, err)
		}
		return nil, fmt.Errorf("%w: trailing JSON value", errInvalidValue)
	}
	return normalized, nil
}

// ValidateCanonical enforces response limits on a normalized JSON data tree
// without invoking any caller-defined encoding behavior.
func ValidateCanonical(value any) error {
	state := canonicalState{}
	if err := state.walk(value, 0); err != nil {
		return fmt.Errorf("%w: %v", errInvalidValue, err)
	}
	return nil
}

func validateNativeStructure(value any) error {
	state := nativeState{active: map[nativeVisit]struct{}{}}
	if err := state.walk(reflect.ValueOf(value), 0, false); err != nil {
		return fmt.Errorf("%w: %v", errInvalidValue, err)
	}
	return nil
}

func (s *nativeState) walk(value reflect.Value, depth int, quoted bool) error {
	if !value.IsValid() {
		return s.countNode(depth, 4)
	}
	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return s.countNode(depth, 4)
		}
		return s.walk(value.Elem(), depth, quoted)
	case reflect.Pointer:
		if value.IsNil() {
			return s.countNode(depth, 4)
		}
	}
	if usesCustomJSONEncoding(value) {
		return s.countNode(depth, 0)
	}
	if value.Kind() == reflect.Pointer {
		release, err := s.enter(value)
		if err != nil {
			return err
		}
		defer release()
		return s.walk(value.Elem(), depth, quoted)
	}

	if err := s.countNode(depth, 0); err != nil {
		return err
	}
	if value.Type() == jsonNumberType {
		numberText := value.String()
		if numberText == "" {
			numberText = "0"
		}
		length := len(numberText)
		if quoted {
			length += 2
		}
		if err := s.addBytes(length); err != nil {
			return err
		}
		if !validJSONNumber(numberText) {
			return errors.New("invalid JSON number")
		}
		if !quoted && numberExceedsSafeMagnitude(json.Number(numberText)) {
			return errors.New("number exceeds JSON safe magnitude")
		}
		return nil
	}
	switch value.Kind() {
	case reflect.Bool:
		length := 4
		if !value.Bool() {
			length = 5
		}
		if quoted {
			length += 2
		}
		return s.addBytes(length)
	case reflect.String:
		if quoted {
			return s.addBytes(quotedJSONStringEncodedLength(value.String()))
		}
		return s.addBytes(jsonStringEncodedLength(value.String()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		integer := value.Int()
		if !quoted && (integer < -maxSafeInteger || integer > maxSafeInteger) {
			return errors.New("integer exceeds JSON safe magnitude")
		}
		length := len(strconv.FormatInt(integer, 10))
		if quoted {
			length += 2
		}
		return s.addBytes(length)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		integer := value.Uint()
		if !quoted && integer > uint64(maxSafeInteger) {
			return errors.New("integer exceeds JSON safe magnitude")
		}
		length := len(strconv.FormatUint(integer, 10))
		if quoted {
			length += 2
		}
		return s.addBytes(length)
	case reflect.Float32, reflect.Float64:
		number := value.Float()
		if math.IsNaN(number) || math.IsInf(number, 0) {
			return errors.New("number must be finite")
		}
		if !quoted && math.Abs(number) > float64(maxSafeInteger) {
			return errors.New("number exceeds JSON safe magnitude")
		}
		length := jsonFloatEncodedLength(number, value.Type().Bits())
		if quoted {
			length += 2
		}
		return s.addBytes(length)
	case reflect.Map:
		if value.IsNil() {
			return s.addBytes(4)
		}
		release, err := s.enter(value)
		if err != nil {
			return err
		}
		defer release()
		if value.Len() > maxNodes-s.nodes {
			return fmt.Errorf("structure exceeds %d nodes", maxNodes)
		}
		if err := s.addBytes(2); err != nil {
			return err
		}
		iterator := value.MapRange()
		index := 0
		for iterator.Next() {
			if index > 0 {
				if err := s.addBytes(1); err != nil {
					return err
				}
			}
			if err := s.countMapKey(iterator.Key()); err != nil {
				return err
			}
			if err := s.walk(iterator.Value(), depth+1, false); err != nil {
				return err
			}
			index++
		}
		return nil
	case reflect.Array:
		if value.Len() > maxNodes-s.nodes {
			return fmt.Errorf("structure exceeds %d nodes", maxNodes)
		}
		if err := s.addBytes(2); err != nil {
			return err
		}
		for index := 0; index < value.Len(); index++ {
			if index > 0 {
				if err := s.addBytes(1); err != nil {
					return err
				}
			}
			if err := s.walk(value.Index(index), depth+1, false); err != nil {
				return err
			}
		}
		return nil
	case reflect.Slice:
		if value.IsNil() {
			return s.addBytes(4)
		}
		release, err := s.enter(value)
		if err != nil {
			return err
		}
		defer release()
		if byteSliceUsesBase64(value.Type()) {
			encodedBytes := (value.Len()+2)/3*4 + 2
			return s.addBytes(encodedBytes)
		}
		if value.Len() > maxNodes-s.nodes {
			return fmt.Errorf("structure exceeds %d nodes", maxNodes)
		}
		if err := s.addBytes(2); err != nil {
			return err
		}
		for index := 0; index < value.Len(); index++ {
			if index > 0 {
				if err := s.addBytes(1); err != nil {
					return err
				}
			}
			if err := s.walk(value.Index(index), depth+1, false); err != nil {
				return err
			}
		}
		return nil
	case reflect.Struct:
		if err := s.addBytes(2); err != nil {
			return err
		}
		emitted := 0
		for _, field := range cachedJSONStructPlan(value.Type()).fields {
			if field.customZero {
				return fmt.Errorf("field %q uses custom IsZero with omitzero", field.name)
			}
			fieldValue, present := jsonPlannedFieldValue(value, field)
			if !present || omitJSONPlannedField(field, fieldValue) {
				continue
			}
			if emitted > 0 {
				if err := s.addBytes(1); err != nil {
					return err
				}
			}
			if err := s.addBytes(jsonStringEncodedLength(field.name) + 1); err != nil {
				return err
			}
			if err := s.walk(fieldValue, depth+1, field.quoted); err != nil {
				return err
			}
			emitted++
		}
		return nil
	case reflect.Invalid:
		return nil
	case reflect.Chan, reflect.Func, reflect.Complex64, reflect.Complex128, reflect.UnsafePointer:
		return fmt.Errorf("unsupported native kind %s", value.Kind())
	default:
		return nil
	}
}

func (s *canonicalState) walk(value any, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("depth exceeds %d", maxDepth)
	}
	s.nodes++
	if s.nodes > maxNodes {
		return fmt.Errorf("structure exceeds %d nodes", maxNodes)
	}
	switch typed := value.(type) {
	case nil:
		return s.addBytes(4)
	case bool:
		if typed {
			return s.addBytes(4)
		}
		return s.addBytes(5)
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) || math.Abs(typed) > float64(maxSafeInteger) {
			return errors.New("number is outside the canonical JSON range")
		}
		return s.addBytes(jsonFloatEncodedLength(typed, 64))
	case string:
		return s.addBytes(jsonStringEncodedLength(typed))
	case []any:
		if err := s.addBytes(2); err != nil {
			return err
		}
		for index, item := range typed {
			if index > 0 {
				if err := s.addBytes(1); err != nil {
					return err
				}
			}
			if err := s.walk(item, depth+1); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		if err := s.addBytes(2); err != nil {
			return err
		}
		index := 0
		for key, item := range typed {
			if index > 0 {
				if err := s.addBytes(1); err != nil {
					return err
				}
			}
			if err := s.addBytes(jsonStringEncodedLength(key) + 1); err != nil {
				return err
			}
			if err := s.walk(item, depth+1); err != nil {
				return err
			}
			index++
		}
		return nil
	default:
		return fmt.Errorf("non-canonical JSON type %T", value)
	}
}

func (s *canonicalState) addBytes(count int) error {
	if count < 0 || count > maxEncodedBytes-s.bytes {
		return fmt.Errorf("encoded value exceeds %d bytes", maxEncodedBytes)
	}
	s.bytes += count
	return nil
}

func (s *nativeState) countNode(depth int, approximateBytes int) error {
	if depth > maxDepth {
		return fmt.Errorf("depth exceeds %d", maxDepth)
	}
	s.nodes++
	if s.nodes > maxNodes {
		return fmt.Errorf("structure exceeds %d nodes", maxNodes)
	}
	return s.addBytes(approximateBytes)
}

func (s *nativeState) addBytes(count int) error {
	if count < 0 || count > maxEncodedBytes-s.approxBytes {
		return fmt.Errorf("encoded value exceeds %d bytes", maxEncodedBytes)
	}
	s.approxBytes += count
	return nil
}

func (s *nativeState) enter(value reflect.Value) (func(), error) {
	visit := nativeVisit{typeName: value.Type(), pointer: value.Pointer()}
	if value.Kind() == reflect.Slice {
		visit.length = value.Len()
		visit.capacity = value.Cap()
	}
	if _, exists := s.active[visit]; exists {
		return nil, errors.New("native value contains a cycle")
	}
	s.active[visit] = struct{}{}
	return func() { delete(s.active, visit) }, nil
}

func (s *nativeState) countMapKey(key reflect.Value) error {
	if key.Kind() == reflect.String {
		return s.addBytes(jsonStringEncodedLength(key.String()) + 1)
	}
	if key.Type().Implements(textMarshalerType) {
		return s.addBytes(3)
	}
	switch key.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return s.addBytes(len(strconv.FormatInt(key.Int(), 10)) + 3)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return s.addBytes(len(strconv.FormatUint(key.Uint(), 10)) + 3)
	default:
		return s.addBytes(3)
	}
}

func usesCustomJSONEncoding(value reflect.Value) bool {
	valueType := value.Type()
	if valueType.Implements(jsonMarshalerType) || valueType.Implements(textMarshalerType) {
		return true
	}
	return valueType.Kind() != reflect.Pointer && value.CanAddr() &&
		(reflect.PointerTo(valueType).Implements(jsonMarshalerType) || reflect.PointerTo(valueType).Implements(textMarshalerType))
}

func byteSliceUsesBase64(sliceType reflect.Type) bool {
	elementType := sliceType.Elem()
	if elementType.Kind() != reflect.Uint8 {
		return false
	}
	pointerType := reflect.PointerTo(elementType)
	return !pointerType.Implements(jsonMarshalerType) && !pointerType.Implements(textMarshalerType)
}

func jsonFloatEncodedLength(number float64, bits int) int {
	magnitude := math.Abs(number)
	format := byte('f')
	if magnitude != 0 && (bits == 64 && (magnitude < 1e-6 || magnitude >= 1e21) ||
		bits == 32 && (float32(magnitude) < 1e-6 || float32(magnitude) >= 1e21)) {
		format = 'e'
	}
	encoded := strconv.FormatFloat(number, format, -1, bits)
	if format == 'e' && len(encoded) >= 4 && encoded[len(encoded)-4] == 'e' && encoded[len(encoded)-3] == '-' && encoded[len(encoded)-2] == '0' {
		return len(encoded) - 1
	}
	return len(encoded)
}

func jsonStringEncodedLength(value string) int {
	length := 2
	for index := 0; index < len(value); {
		character := value[index]
		if character < utf8.RuneSelf {
			index++
			switch character {
			case '\\', '"', '\b', '\f', '\n', '\r', '\t':
				length += 2
			case '<', '>', '&':
				length += 6
			default:
				if character < 0x20 {
					length += 6
				} else {
					length++
				}
			}
			if length > maxEncodedBytes {
				return maxEncodedBytes + 1
			}
			continue
		}
		runeValue, size := utf8.DecodeRuneInString(value[index:])
		index += size
		if runeValue == utf8.RuneError && size == 1 || runeValue == '\u2028' || runeValue == '\u2029' {
			length += 6
		} else {
			length += size
		}
		if length > maxEncodedBytes {
			return maxEncodedBytes + 1
		}
	}
	return length
}

func quotedJSONStringEncodedLength(value string) int {
	length := 6 // outer quotes plus escaped inner quotes
	for index := 0; index < len(value); {
		character := value[index]
		if character < utf8.RuneSelf {
			index++
			switch character {
			case '\\', '"':
				length += 4
			case '\b', '\f', '\n', '\r', '\t':
				length += 3
			case '<', '>', '&':
				length += 7
			default:
				if character < 0x20 {
					length += 7
				} else {
					length++
				}
			}
			if length > maxEncodedBytes {
				return maxEncodedBytes + 1
			}
			continue
		}
		runeValue, size := utf8.DecodeRuneInString(value[index:])
		index += size
		if runeValue == utf8.RuneError && size == 1 || runeValue == '\u2028' || runeValue == '\u2029' {
			length += 7
		} else {
			length += size
		}
		if length > maxEncodedBytes {
			return maxEncodedBytes + 1
		}
	}
	return length
}

func validJSONNumber(value string) bool {
	if value == "" {
		return false
	}
	if value[0] == '-' {
		value = value[1:]
		if value == "" {
			return false
		}
	}
	switch {
	case value[0] == '0':
		value = value[1:]
	case '1' <= value[0] && value[0] <= '9':
		value = value[1:]
		for len(value) > 0 && '0' <= value[0] && value[0] <= '9' {
			value = value[1:]
		}
	default:
		return false
	}
	if len(value) >= 2 && value[0] == '.' && '0' <= value[1] && value[1] <= '9' {
		value = value[2:]
		for len(value) > 0 && '0' <= value[0] && value[0] <= '9' {
			value = value[1:]
		}
	}
	if len(value) >= 2 && (value[0] == 'e' || value[0] == 'E') {
		value = value[1:]
		if value[0] == '+' || value[0] == '-' {
			value = value[1:]
			if value == "" {
				return false
			}
		}
		for len(value) > 0 && '0' <= value[0] && value[0] <= '9' {
			value = value[1:]
		}
	}
	return value == ""
}

func numberExceedsSafeMagnitude(number json.Number) bool {
	text := number.String()
	if text == "" {
		return false
	}
	if text[0] == '-' {
		text = text[1:]
	}
	exponentIndex := strings.IndexAny(text, "eE")
	mantissa := text
	exponent := 0
	if exponentIndex >= 0 {
		mantissa = text[:exponentIndex]
		exponent = boundedDecimalExponent(text[exponentIndex+1:])
	}
	dotIndex := strings.IndexByte(mantissa, '.')
	integerDigits := len(mantissa)
	if dotIndex >= 0 {
		integerDigits = dotIndex
	}
	digits := strings.ReplaceAll(mantissa, ".", "")
	leadingZeros := 0
	for leadingZeros < len(digits) && digits[leadingZeros] == '0' {
		leadingZeros++
	}
	if leadingZeros == len(digits) {
		return false
	}
	effectiveIntegerDigits := integerDigits + exponent - leadingZeros
	const safeDigits = "9007199254740991"
	if effectiveIntegerDigits != len(safeDigits) {
		return effectiveIntegerDigits > len(safeDigits)
	}
	significant := digits[leadingZeros:]
	for index := range len(safeDigits) {
		digit := byte('0')
		if index < len(significant) {
			digit = significant[index]
		}
		if digit != safeDigits[index] {
			return digit > safeDigits[index]
		}
	}
	for index := len(safeDigits); index < len(significant); index++ {
		if significant[index] != '0' {
			return true
		}
	}
	return false
}

func boundedDecimalExponent(text string) int {
	sign := 1
	if text != "" && (text[0] == '+' || text[0] == '-') {
		if text[0] == '-' {
			sign = -1
		}
		text = text[1:]
	}
	const limit = maxEncodedBytes + 32
	value := 0
	for index := 0; index < len(text); index++ {
		if value > (limit-int(text[index]-'0'))/10 {
			return sign * limit
		}
		value = value*10 + int(text[index]-'0')
	}
	return sign * value
}

func (s *decoderState) readValue(depth int) (any, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("%w: depth exceeds %d", errInvalidValue, maxDepth)
	}
	s.nodes++
	if s.nodes > maxNodes {
		return nil, fmt.Errorf("%w: structure exceeds %d nodes", errInvalidValue, maxNodes)
	}

	token, err := s.decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidValue, err)
	}
	switch typed := token.(type) {
	case nil, bool, string:
		return typed, nil
	case json.Number:
		if numberExceedsSafeMagnitude(typed) {
			return nil, fmt.Errorf("%w: number exceeds JSON safe magnitude", errInvalidValue)
		}
		number, err := strconv.ParseFloat(typed.String(), 64)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid number", errInvalidValue)
		}
		return number, nil
	case json.Delim:
		switch typed {
		case '{':
			return s.readObject(depth)
		case '[':
			return s.readArray(depth)
		default:
			return nil, fmt.Errorf("%w: unexpected delimiter %q", errInvalidValue, typed)
		}
	default:
		return nil, fmt.Errorf("%w: unsupported token %T", errInvalidValue, token)
	}
}

func (s *decoderState) readObject(depth int) (map[string]any, error) {
	result := map[string]any{}
	for s.decoder.More() {
		keyToken, err := s.decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errInvalidValue, err)
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, fmt.Errorf("%w: object key is not a string", errInvalidValue)
		}
		if isPrototypeSensitiveKey(key) {
			return nil, fmt.Errorf("%w: object key %q is forbidden", errInvalidValue, key)
		}
		if _, exists := result[key]; exists {
			return nil, fmt.Errorf("%w: duplicate object key %q", errInvalidValue, key)
		}
		value, err := s.readValue(depth + 1)
		if err != nil {
			return nil, err
		}
		result[key] = value
	}
	closing, err := s.decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidValue, err)
	}
	if closing != json.Delim('}') {
		return nil, fmt.Errorf("%w: object is not terminated", errInvalidValue)
	}
	return result, nil
}

func (s *decoderState) readArray(depth int) ([]any, error) {
	result := []any{}
	for s.decoder.More() {
		value, err := s.readValue(depth + 1)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	closing, err := s.decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidValue, err)
	}
	if closing != json.Delim(']') {
		return nil, fmt.Errorf("%w: array is not terminated", errInvalidValue)
	}
	return result, nil
}

func isPrototypeSensitiveKey(key string) bool {
	return key == "__proto__" || key == "constructor" || key == "prototype"
}
