package capabilitycontract

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var prototypeSensitivePropertyNames = map[string]struct{}{
	"__proto__":   {},
	"constructor": {},
	"prototype":   {},
}

const (
	MaxSchemaDepth      = 32
	MaxSchemaNodes      = 4096
	MaxSchemaProperties = 1024
	MaxSchemaEnumValues = 1024
	MaxSchemaBranches   = 64
)

func ValidateValue(schema map[string]any, value any) error {
	if err := validateSchema(schema, "schema"); err != nil {
		return err
	}
	if !validateRestrictedValue(value, schema, map[containerIdentity]struct{}{}) {
		return errors.New("value does not match the restricted host capability schema")
	}
	return nil
}

func validateSchema(schema map[string]any, label string) error {
	if err := validateSchemaBudget(schema, label); err != nil {
		return err
	}
	return validateSchemaShape(schema, label)
}

func validateSchemaShape(schema map[string]any, label string) error {
	if schema == nil {
		return invalid("%s is required", label)
	}
	if err := validateSchemaMetadata(schema, label); err != nil {
		return err
	}
	allowed := map[string]bool{"description": true, "title": true}
	if rawBranches, ok := schema["oneOf"]; ok {
		if _, hasType := schema["type"]; hasType {
			return invalid("%s must not combine type and oneOf", label)
		}
		allowed["oneOf"] = true
		branches, err := schemaBranches(rawBranches, label+".oneOf")
		if err != nil {
			return err
		}
		for index, branch := range branches {
			if err := validateSchemaShape(branch, fmt.Sprintf("%s.oneOf[%d]", label, index)); err != nil {
				return err
			}
		}
		if err := rejectDuplicateSchemaBranches(branches, label+".oneOf"); err != nil {
			return err
		}
		return validateSchemaKeys(schema, allowed, label)
	}
	typeName, ok := schema["type"].(string)
	if !ok {
		return invalid("%s.type must be a string", label)
	}
	allowed["type"] = true
	switch typeName {
	case "object":
		allowed["properties"] = true
		allowed["required"] = true
		allowed["additionalProperties"] = true
		allowed["minProperties"] = true
		allowed["maxProperties"] = true
		properties := map[string]any{}
		if rawProperties, exists := schema["properties"]; exists {
			var ok bool
			properties, ok = rawProperties.(map[string]any)
			if !ok {
				return invalid("%s.properties must be an object", label)
			}
		}
		if schema["additionalProperties"] != false {
			return invalid("%s.additionalProperties must be false", label)
		}
		for name, raw := range properties {
			if _, forbidden := prototypeSensitivePropertyNames[name]; forbidden {
				return invalid("%s.properties contains forbidden property %q", label, name)
			}
			child, ok := raw.(map[string]any)
			if !ok {
				return invalid("%s.properties.%s must be an object", label, name)
			}
			if err := validateSchemaShape(child, label+".properties."+name); err != nil {
				return err
			}
		}
		required, err := schemaStringArray(schema["required"], label+".required")
		if err != nil {
			return err
		}
		for _, name := range required {
			if _, ok := properties[name]; !ok {
				return invalid("%s.required contains unknown property %q", label, name)
			}
		}
		if err := validateIntegerBounds(schema, label, "minProperties", "maxProperties"); err != nil {
			return err
		}
	case "array":
		allowed["items"] = true
		allowed["minItems"] = true
		allowed["maxItems"] = true
		allowed["uniqueItems"] = true
		items, ok := schema["items"].(map[string]any)
		if !ok {
			return invalid("%s.items must be an object", label)
		}
		if err := validateSchemaShape(items, label+".items"); err != nil {
			return err
		}
		if err := validateIntegerBounds(schema, label, "minItems", "maxItems"); err != nil {
			return err
		}
		if value, ok := schema["uniqueItems"]; ok {
			if _, ok := value.(bool); !ok {
				return invalid("%s.uniqueItems must be a boolean", label)
			}
		}
	case "string":
		allowed["enum"] = true
		allowed["const"] = true
		allowed["minLength"] = true
		allowed["maxLength"] = true
		allowed["pattern"] = true
		allowed["format"] = true
		if pattern, ok := schema["pattern"].(string); ok {
			if !portablePatternSyntax.MatchString(pattern) {
				return invalid("%s.pattern is outside the portable full-match dialect", label)
			}
			if _, err := regexp.Compile(pattern); err != nil {
				return invalid("%s.pattern is invalid", label)
			}
		}
		if err := validateIntegerBounds(schema, label, "minLength", "maxLength"); err != nil {
			return err
		}
		if err := validateTypedEnum(schema["enum"], label+".enum", func(value any) bool { _, ok := value.(string); return ok }); err != nil {
			return err
		}
		if value, ok := schema["const"]; ok {
			if _, ok := value.(string); !ok {
				return invalid("%s.const must be a string", label)
			}
		}
		if value, ok := schema["format"]; ok {
			format, ok := value.(string)
			if !ok || !supportedStringFormat(format) {
				return invalid("%s.format is unsupported", label)
			}
		}
	case "integer", "number":
		allowed["enum"] = true
		allowed["const"] = true
		allowed["minimum"] = true
		allowed["maximum"] = true
		allowed["exclusiveMinimum"] = true
		allowed["exclusiveMaximum"] = true
		allowed["multipleOf"] = true
		integerOnly := typeName == "integer"
		if err := validateNumericKeywords(schema, label, integerOnly); err != nil {
			return err
		}
	case "boolean", "null":
		allowed["const"] = true
		if value, ok := schema["const"]; ok {
			if typeName == "boolean" {
				if _, ok := value.(bool); !ok {
					return invalid("%s.const must be a boolean", label)
				}
			} else if value != nil {
				return invalid("%s.const must be null", label)
			}
		}
	default:
		return invalid("%s.type %q is unsupported", label, typeName)
	}
	return validateSchemaKeys(schema, allowed, label)
}

type schemaBudget struct {
	nodes      int
	properties int
	enumValues int
	branches   int
}

func validateSchemaBudget(schema map[string]any, label string) error {
	budget := schemaBudget{}
	return walkSchemaBudget(schema, label, 1, &budget, map[containerIdentity]struct{}{})
}

func walkSchemaBudget(value any, label string, depth int, budget *schemaBudget, seen map[containerIdentity]struct{}) error {
	if depth > MaxSchemaDepth {
		return invalid("%s exceeds the maximum schema depth", label)
	}
	budget.nodes++
	if budget.nodes > MaxSchemaNodes {
		return invalid("%s exceeds the maximum schema node count", label)
	}
	switch typed := value.(type) {
	case map[string]any:
		identity := containerIdentity(fmt.Sprintf("map:%p", typed))
		if _, exists := seen[identity]; exists {
			return invalid("%s contains a cyclic schema value", label)
		}
		seen[identity] = struct{}{}
		defer delete(seen, identity)
		if properties, ok := typed["properties"].(map[string]any); ok {
			budget.properties += len(properties)
			if budget.properties > MaxSchemaProperties {
				return invalid("%s exceeds the maximum schema property count", label)
			}
		}
		if enum, ok := typed["enum"].([]any); ok {
			budget.enumValues += len(enum)
			if budget.enumValues > MaxSchemaEnumValues {
				return invalid("%s exceeds the maximum schema enum value count", label)
			}
		}
		if branches, ok := typed["oneOf"].([]any); ok {
			budget.branches += len(branches)
			if budget.branches > MaxSchemaBranches {
				return invalid("%s exceeds the maximum schema branch count", label)
			}
		}
		for key, child := range typed {
			if err := walkSchemaBudget(child, label+"."+key, depth+1, budget, seen); err != nil {
				return err
			}
		}
	case []any:
		identity := containerIdentity(fmt.Sprintf("slice:%p", typed))
		if _, exists := seen[identity]; exists {
			return invalid("%s contains a cyclic schema value", label)
		}
		seen[identity] = struct{}{}
		defer delete(seen, identity)
		for index, child := range typed {
			if err := walkSchemaBudget(child, fmt.Sprintf("%s[%d]", label, index), depth+1, budget, seen); err != nil {
				return err
			}
		}
	}
	return nil
}

var (
	portablePatternSyntax = regexp.MustCompile(`^\^(?:(?:[A-Za-z0-9_~:/-]|\\[.\\-]|\[[A-Za-z0-9._~:/-]+\])(?:[+*?]|\{(?:0|[1-9][0-9]*)(?:,(?:0|[1-9][0-9]*)?)?\})?)+\$$`)
	dateTimePattern       = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})$`)
	uuidPattern           = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	hostnameLabelPattern  = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$`)
	ipv4PartPattern       = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,2})$`)
	ipv6GroupPattern      = regexp.MustCompile(`^[0-9A-Fa-f]{1,4}$`)
)

type containerIdentity string

func validateRestrictedValue(value any, schema map[string]any, seen map[containerIdentity]struct{}) bool {
	if rawBranches, ok := schema["oneOf"]; ok {
		branches, err := schemaBranches(rawBranches, "oneOf")
		if err != nil {
			return false
		}
		matches := 0
		for _, branch := range branches {
			if validateRestrictedValue(value, branch, seen) {
				matches++
			}
		}
		return matches == 1
	}
	typeName, ok := schema["type"].(string)
	if !ok {
		return false
	}
	identity, tracked := restrictedContainerIdentity(value)
	if tracked {
		if _, exists := seen[identity]; exists {
			return false
		}
		seen[identity] = struct{}{}
		defer delete(seen, identity)
	}
	switch typeName {
	case "object":
		return validateRestrictedObject(value, schema, seen)
	case "array":
		return validateRestrictedArray(value, schema, seen)
	case "string":
		return validateRestrictedString(value, schema)
	case "integer":
		number, valid := restrictedNumber(value, true)
		return valid && validateRestrictedNumber(number, schema)
	case "number":
		number, valid := restrictedNumber(value, false)
		return valid && validateRestrictedNumber(number, schema)
	case "boolean":
		boolean, valid := value.(bool)
		return valid && restrictedConstEqual(boolean, schema)
	case "null":
		return value == nil
	default:
		return false
	}
}

func restrictedContainerIdentity(value any) (containerIdentity, bool) {
	switch typed := value.(type) {
	case map[string]any:
		return containerIdentity(fmt.Sprintf("map:%p", typed)), true
	case []any:
		if len(typed) == 0 {
			return "", false
		}
		return containerIdentity(fmt.Sprintf("slice:%p", typed)), true
	default:
		return "", false
	}
}

func validateRestrictedObject(value any, schema map[string]any, seen map[containerIdentity]struct{}) bool {
	object, ok := value.(map[string]any)
	if !ok || schema["additionalProperties"] != false {
		return false
	}
	properties, _ := schema["properties"].(map[string]any)
	required, err := schemaStringArray(schema["required"], "required")
	if err != nil {
		return false
	}
	for _, name := range required {
		if _, exists := object[name]; !exists {
			return false
		}
	}
	if !restrictedIntegerBound(len(object), schema["minProperties"], schema["maxProperties"]) {
		return false
	}
	for name, item := range object {
		rawChild, exists := properties[name]
		child, valid := rawChild.(map[string]any)
		if !exists || !valid || !validateRestrictedValue(item, child, seen) {
			return false
		}
	}
	return true
}

func validateRestrictedArray(value any, schema map[string]any, seen map[containerIdentity]struct{}) bool {
	items, ok := value.([]any)
	child, childOK := schema["items"].(map[string]any)
	if !ok || !childOK || !restrictedIntegerBound(len(items), schema["minItems"], schema["maxItems"]) {
		return false
	}
	if schema["uniqueItems"] == true {
		unique := make(map[string]struct{}, len(items))
		for _, item := range items {
			key, err := restrictedJSONKey(item)
			if err != nil {
				return false
			}
			if _, exists := unique[key]; exists {
				return false
			}
			unique[key] = struct{}{}
		}
	}
	for _, item := range items {
		if !validateRestrictedValue(item, child, seen) {
			return false
		}
	}
	return true
}

func validateRestrictedString(value any, schema map[string]any) bool {
	text, ok := value.(string)
	if !ok || !restrictedIntegerBound(utf8.RuneCountInString(text), schema["minLength"], schema["maxLength"]) || !restrictedConstEqual(text, schema) {
		return false
	}
	if rawEnum, ok := schema["enum"].([]any); ok {
		matched := false
		for _, candidate := range rawEnum {
			if candidate == text {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if pattern, ok := schema["pattern"].(string); ok {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}
		match := compiled.FindStringIndex(text)
		if len(match) != 2 || match[0] != 0 || match[1] != len(text) {
			return false
		}
	}
	if format, ok := schema["format"].(string); ok && !validateRestrictedStringFormat(text, format) {
		return false
	}
	return true
}

func validateRestrictedStringFormat(value, format string) bool {
	switch format {
	case "date-time":
		match := dateTimePattern.FindStringSubmatch(value)
		if len(match) != 8 {
			return false
		}
		hour, _ := strconv.Atoi(match[4])
		minute, _ := strconv.Atoi(match[5])
		second, _ := strconv.Atoi(match[6])
		if hour > 23 || minute > 59 || second > 59 {
			return false
		}
		if match[7] != "Z" {
			offsetHour, _ := strconv.Atoi(match[7][1:3])
			offsetMinute, _ := strconv.Atoi(match[7][4:6])
			if offsetHour > 23 || offsetMinute > 59 {
				return false
			}
		}
		_, err := time.Parse(time.RFC3339Nano, value)
		return err == nil
	case "uuid":
		return uuidPattern.MatchString(value)
	case "hostname":
		if len(value) == 0 || len(value) > 253 || strings.HasSuffix(value, ".") {
			return false
		}
		for _, label := range strings.Split(value, ".") {
			if len(label) == 0 || len(label) > 63 || !hostnameLabelPattern.MatchString(label) {
				return false
			}
		}
		return true
	case "ipv4":
		return validateRestrictedIPv4(value)
	case "ipv6":
		return validateRestrictedIPv6(value)
	default:
		return false
	}
}

func validateRestrictedIPv4(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if !ipv4PartPattern.MatchString(part) {
			return false
		}
		number, _ := strconv.Atoi(part)
		if number > 255 {
			return false
		}
	}
	return true
}

func validateRestrictedIPv6(value string) bool {
	if value == "" || strings.Contains(value, ":::") || strings.Count(value, "::") > 1 {
		return false
	}
	compression := strings.Index(value, "::")
	leftRaw, rightRaw := value, ""
	if compression >= 0 {
		leftRaw = value[:compression]
		rightRaw = value[compression+2:]
	}
	left := splitNonEmptyColon(leftRaw)
	right := splitNonEmptyColon(rightRaw)
	leftGroups, ok := restrictedIPv6Groups(left, len(right) == 0)
	if !ok {
		return false
	}
	rightGroups, ok := restrictedIPv6Groups(right, true)
	if !ok {
		return false
	}
	groups := leftGroups + rightGroups
	if compression >= 0 {
		return groups < 8
	}
	return groups == 8
}

func splitNonEmptyColon(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ":")
}

func restrictedIPv6Groups(parts []string, allowIPv4 bool) (int, bool) {
	groups := 0
	for index, part := range parts {
		if strings.Contains(part, ".") {
			if !allowIPv4 || index != len(parts)-1 || !validateRestrictedIPv4(part) {
				return 0, false
			}
			groups += 2
			continue
		}
		if !ipv6GroupPattern.MatchString(part) {
			return 0, false
		}
		groups++
	}
	return groups, true
}

func validateRestrictedNumber(value float64, schema map[string]any) bool {
	if !restrictedConstEqual(value, schema) {
		return false
	}
	if rawEnum, ok := schema["enum"].([]any); ok {
		matched := false
		for _, candidate := range rawEnum {
			candidateNumber, valid := restrictedNumber(candidate, false)
			if valid && candidateNumber == value {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if minimum, ok := restrictedSchemaNumber(schema["minimum"]); ok && value < minimum {
		return false
	}
	if maximum, ok := restrictedSchemaNumber(schema["maximum"]); ok && value > maximum {
		return false
	}
	if minimum, ok := restrictedSchemaNumber(schema["exclusiveMinimum"]); ok && value <= minimum {
		return false
	}
	if maximum, ok := restrictedSchemaNumber(schema["exclusiveMaximum"]); ok && value >= maximum {
		return false
	}
	if divisor, ok := restrictedSchemaNumber(schema["multipleOf"]); ok && !restrictedDecimalMultiple(value, divisor) {
		return false
	}
	return true
}

func restrictedNumber(value any, integerOnly bool) (float64, bool) {
	var number float64
	switch typed := value.(type) {
	case int:
		number = float64(typed)
	case int8:
		number = float64(typed)
	case int16:
		number = float64(typed)
	case int32:
		number = float64(typed)
	case int64:
		number = float64(typed)
	case uint:
		number = float64(typed)
	case uint8:
		number = float64(typed)
	case uint16:
		number = float64(typed)
	case uint32:
		number = float64(typed)
	case uint64:
		number = float64(typed)
	case float32:
		number = float64(typed)
	case float64:
		number = typed
	case json.Number:
		parsed, err := strconv.ParseFloat(string(typed), 64)
		if err != nil {
			return 0, false
		}
		number = parsed
	default:
		return 0, false
	}
	if math.IsNaN(number) || math.IsInf(number, 0) {
		return 0, false
	}
	if integerOnly && (math.Trunc(number) != number || math.Abs(number) > 9007199254740991) {
		return 0, false
	}
	return number, true
}

func restrictedSchemaNumber(value any) (float64, bool) {
	if value == nil {
		return 0, false
	}
	return restrictedNumber(value, false)
}

func restrictedDecimalMultiple(value, divisor float64) bool {
	if divisor <= 0 || math.IsNaN(divisor) || math.IsInf(divisor, 0) {
		return false
	}
	valueCoefficient, valueScale, ok := decimalCoefficient(value)
	if !ok {
		return false
	}
	divisorCoefficient, divisorScale, ok := decimalCoefficient(divisor)
	if !ok || divisorCoefficient.Sign() == 0 {
		return false
	}
	numerator := new(big.Int).Set(valueCoefficient)
	denominator := new(big.Int).Set(divisorCoefficient)
	if difference := divisorScale - valueScale; difference > 0 {
		numerator.Mul(numerator, decimalPower(difference))
	} else if difference < 0 {
		denominator.Mul(denominator, decimalPower(-difference))
	}
	remainder := new(big.Int).Rem(numerator, denominator)
	return remainder.Sign() == 0
}

func decimalCoefficient(value float64) (*big.Int, int, bool) {
	text := strconv.FormatFloat(value, 'g', -1, 64)
	sign := 1
	if strings.HasPrefix(text, "-") {
		sign = -1
		text = text[1:]
	}
	exponent := 0
	if index := strings.IndexAny(text, "eE"); index >= 0 {
		parsed, err := strconv.Atoi(text[index+1:])
		if err != nil {
			return nil, 0, false
		}
		exponent = parsed
		text = text[:index]
	}
	scale := 0
	if index := strings.IndexByte(text, '.'); index >= 0 {
		scale = len(text) - index - 1
		text = text[:index] + text[index+1:]
	}
	text = strings.TrimLeft(text, "0")
	if text == "" {
		return big.NewInt(0), 0, true
	}
	coefficient := new(big.Int)
	if _, ok := coefficient.SetString(text, 10); !ok {
		return nil, 0, false
	}
	if sign < 0 {
		coefficient.Neg(coefficient)
	}
	return coefficient, scale - exponent, true
}

func decimalPower(exponent int) *big.Int {
	return new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(exponent)), nil)
}

func restrictedConstEqual(value any, schema map[string]any) bool {
	constant, exists := schema["const"]
	if !exists {
		return true
	}
	left, err := restrictedJSONKey(value)
	if err != nil {
		return false
	}
	right, err := restrictedJSONKey(constant)
	return err == nil && left == right
}

func restrictedIntegerBound(value int, minimum, maximum any) bool {
	if raw, ok := schemaOptionalNumber(minimum, true); ok && float64(value) < raw {
		return false
	}
	if raw, ok := schemaOptionalNumber(maximum, true); ok && float64(value) > raw {
		return false
	}
	return true
}

func restrictedJSONKey(value any) (string, error) {
	switch typed := value.(type) {
	case nil:
		return "null", nil
	case bool:
		if typed {
			return "true", nil
		}
		return "false", nil
	case string:
		raw, _ := json.Marshal(typed)
		return string(raw), nil
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			encodedKey, _ := json.Marshal(key)
			encodedValue, err := restrictedJSONKey(typed[key])
			if err != nil {
				return "", err
			}
			parts = append(parts, string(encodedKey)+":"+encodedValue)
		}
		return "{" + strings.Join(parts, ",") + "}", nil
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			encoded, err := restrictedJSONKey(item)
			if err != nil {
				return "", err
			}
			parts = append(parts, encoded)
		}
		return "[" + strings.Join(parts, ",") + "]", nil
	default:
		number, ok := restrictedNumber(value, false)
		if !ok {
			return "", errors.New("value is not canonical JSON")
		}
		if number == 0 {
			return "0", nil
		}
		return strconv.FormatFloat(number, 'g', -1, 64), nil
	}
}

func validateSchemaMetadata(schema map[string]any, label string) error {
	for _, key := range []string{"title", "description"} {
		if value, ok := schema[key]; ok {
			if _, ok := value.(string); !ok {
				return invalid("%s.%s must be a string", label, key)
			}
		}
	}
	return nil
}

func rejectDuplicateSchemaBranches(branches []map[string]any, label string) error {
	seen := map[string]struct{}{}
	for index, branch := range branches {
		raw, err := json.Marshal(branch)
		if err != nil {
			return invalid("%s[%d] cannot be canonicalized", label, index)
		}
		key := string(raw)
		if _, exists := seen[key]; exists {
			return invalid("%s[%d] duplicates another branch", label, index)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateIntegerBounds(schema map[string]any, label string, minimumKey string, maximumKey string) error {
	minimum, hasMinimum, err := schemaInteger(schema[minimumKey])
	if err != nil {
		return invalid("%s.%s must be a non-negative integer", label, minimumKey)
	}
	maximum, hasMaximum, err := schemaInteger(schema[maximumKey])
	if err != nil {
		return invalid("%s.%s must be a non-negative integer", label, maximumKey)
	}
	if hasMinimum && minimum < 0 || hasMaximum && maximum < 0 {
		return invalid("%s bounds must be non-negative", label)
	}
	if hasMinimum && hasMaximum && minimum > maximum {
		return invalid("%s.%s must not exceed %s", label, minimumKey, maximumKey)
	}
	return nil
}

func validateNumericKeywords(schema map[string]any, label string, integerOnly bool) error {
	for _, key := range []string{"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf", "const"} {
		value, ok := schema[key]
		if !ok {
			continue
		}
		number, valid := schemaNumber(value, integerOnly)
		if !valid {
			return invalid("%s.%s must be a valid number", label, key)
		}
		if key == "multipleOf" && number <= 0 {
			return invalid("%s.multipleOf must be positive", label)
		}
	}
	if err := validateTypedEnum(schema["enum"], label+".enum", func(value any) bool {
		_, ok := schemaNumber(value, integerOnly)
		return ok
	}); err != nil {
		return err
	}
	minimum, hasMinimum := schemaOptionalNumber(schema["minimum"], integerOnly)
	maximum, hasMaximum := schemaOptionalNumber(schema["maximum"], integerOnly)
	if hasMinimum && hasMaximum && minimum > maximum {
		return invalid("%s.minimum must not exceed maximum", label)
	}
	exclusiveMinimum, hasExclusiveMinimum := schemaOptionalNumber(schema["exclusiveMinimum"], integerOnly)
	exclusiveMaximum, hasExclusiveMaximum := schemaOptionalNumber(schema["exclusiveMaximum"], integerOnly)
	if hasExclusiveMinimum && hasExclusiveMaximum && exclusiveMinimum >= exclusiveMaximum {
		return invalid("%s.exclusiveMinimum must be less than exclusiveMaximum", label)
	}
	return nil
}

func validateTypedEnum(value any, label string, valid func(any) bool) error {
	if value == nil {
		return nil
	}
	items, ok := value.([]any)
	if !ok || len(items) == 0 {
		return invalid("%s must be a non-empty array", label)
	}
	seen := map[string]struct{}{}
	for index, item := range items {
		if !valid(item) {
			return invalid("%s[%d] has an invalid type", label, index)
		}
		raw, _ := json.Marshal(item)
		if _, exists := seen[string(raw)]; exists {
			return invalid("%s[%d] is duplicated", label, index)
		}
		seen[string(raw)] = struct{}{}
	}
	return nil
}

func schemaInteger(value any) (int64, bool, error) {
	if value == nil {
		return 0, false, nil
	}
	number, ok := schemaNumber(value, true)
	if !ok {
		return 0, true, errors.New("not an integer")
	}
	return int64(number), true, nil
}

func schemaNumber(value any, integerOnly bool) (float64, bool) {
	var number float64
	switch typed := value.(type) {
	case int:
		number = float64(typed)
	case int32:
		number = float64(typed)
	case int64:
		number = float64(typed)
	case uint:
		number = float64(typed)
	case uint32:
		number = float64(typed)
	case uint64:
		number = float64(typed)
	case float64:
		number = typed
	case json.Number:
		parsed, err := typed.Float64()
		if err != nil {
			return 0, false
		}
		number = parsed
	default:
		return 0, false
	}
	if math.IsNaN(number) || math.IsInf(number, 0) || integerOnly && math.Trunc(number) != number {
		return 0, false
	}
	return number, true
}

func schemaOptionalNumber(value any, integerOnly bool) (float64, bool) {
	if value == nil {
		return 0, false
	}
	number, ok := schemaNumber(value, integerOnly)
	return number, ok
}

func supportedStringFormat(value string) bool {
	switch strings.TrimSpace(value) {
	case "date-time", "uuid", "hostname", "ipv4", "ipv6":
		return true
	default:
		return false
	}
}

func validateSchemaKeys(schema map[string]any, allowed map[string]bool, label string) error {
	keys := make([]string, 0, len(schema))
	for key := range schema {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !allowed[key] {
			return invalid("%s.%s is unsupported", label, key)
		}
	}
	return nil
}

func schemaBranches(value any, label string) ([]map[string]any, error) {
	raw, ok := value.([]any)
	if !ok || len(raw) < 2 || len(raw) > 8 {
		return nil, invalid("%s must contain between 2 and 8 schemas", label)
	}
	branches := make([]map[string]any, 0, len(raw))
	for index, item := range raw {
		branch, ok := item.(map[string]any)
		if !ok {
			return nil, invalid("%s[%d] must be an object", label, index)
		}
		branches = append(branches, branch)
	}
	return branches, nil
}

func schemaStringArray(value any, label string) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	var raw []any
	switch typed := value.(type) {
	case []any:
		raw = typed
	case []string:
		raw = make([]any, len(typed))
		for index, item := range typed {
			raw[index] = item
		}
	default:
		return nil, invalid("%s must be an array of strings", label)
	}
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for index, item := range raw {
		text, ok := item.(string)
		if !ok || text == "" || strings.IndexFunc(text, unicode.IsSpace) >= 0 {
			return nil, invalid("%s[%d] must be a non-empty string without whitespace", label, index)
		}
		if _, exists := seen[text]; exists {
			return nil, invalid("%s[%d] is duplicated", label, index)
		}
		seen[text] = struct{}{}
		out = append(out, text)
	}
	return out, nil
}

func schemaTypeScript(schema map[string]any, indent string) (string, error) {
	if rawBranches, ok := schema["oneOf"]; ok {
		branches, err := schemaBranches(rawBranches, "oneOf")
		if err != nil {
			return "", err
		}
		parts := make([]string, 0, len(branches))
		for _, branch := range branches {
			text, err := schemaTypeScript(branch, indent)
			if err != nil {
				return "", err
			}
			parts = append(parts, text)
		}
		return stringsJoin(parts, " | "), nil
	}
	typeName, _ := schema["type"].(string)
	switch typeName {
	case "object":
		properties, _ := schema["properties"].(map[string]any)
		requiredList, err := schemaStringArray(schema["required"], "required")
		if err != nil {
			return "", err
		}
		required := map[string]bool{}
		for _, name := range requiredList {
			required[name] = true
		}
		keys := make([]string, 0, len(properties))
		for key := range properties {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		var out string
		out += "{\n"
		for _, key := range keys {
			child, _ := properties[key].(map[string]any)
			typeText, err := schemaTypeScript(child, indent+"  ")
			if err != nil {
				return "", err
			}
			property := fmt.Sprintf("%q", key)
			if identifierPattern.MatchString(key) {
				property = key
			}
			optional := "?"
			if required[key] {
				optional = ""
			}
			out += fmt.Sprintf("%s  %s%s: %s;\n", indent, property, optional, typeText)
		}
		out += indent + "}"
		return out, nil
	case "array":
		items, _ := schema["items"].(map[string]any)
		itemType, err := schemaTypeScript(items, indent)
		if err != nil {
			return "", err
		}
		return "Array<" + itemType + ">", nil
	case "string":
		if enumValues, ok := schema["enum"].([]any); ok && len(enumValues) > 0 {
			parts := make([]string, 0, len(enumValues))
			for _, item := range enumValues {
				value, ok := item.(string)
				if !ok {
					return "", invalid("string enum contains a non-string value")
				}
				parts = append(parts, fmt.Sprintf("%q", value))
			}
			return stringsJoin(parts, " | "), nil
		}
		if value, ok := schema["const"].(string); ok {
			return fmt.Sprintf("%q", value), nil
		}
		return "string", nil
	case "integer", "number":
		if enumValues, ok := schema["enum"].([]any); ok && len(enumValues) > 0 {
			parts := make([]string, 0, len(enumValues))
			for _, item := range enumValues {
				literal, err := primitiveTypeScriptLiteral(item)
				if err != nil {
					return "", err
				}
				parts = append(parts, literal)
			}
			return stringsJoin(parts, " | "), nil
		}
		if value, ok := schema["const"]; ok {
			return primitiveTypeScriptLiteral(value)
		}
		return "number", nil
	case "boolean":
		if value, ok := schema["const"].(bool); ok {
			if value {
				return "true", nil
			}
			return "false", nil
		}
		return "boolean", nil
	case "null":
		return "null", nil
	default:
		return "", invalid("unsupported schema type %q", typeName)
	}
}

func primitiveTypeScriptLiteral(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	literal := string(raw)
	if literal == "null" || literal == "true" || literal == "false" || json.Valid(raw) && len(raw) > 0 && (raw[0] == '-' || raw[0] >= '0' && raw[0] <= '9') {
		return literal, nil
	}
	return "", invalid("primitive literal %q is unsupported", literal)
}

func stringsJoin(values []string, separator string) string {
	if len(values) == 0 {
		return ""
	}
	out := values[0]
	for _, value := range values[1:] {
		out += separator + value
	}
	return out
}
