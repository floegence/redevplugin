package jsonvalue

import (
	"reflect"
	"slices"
	"strings"
	"sync"
	"unicode"
)

type jsonTagOptions string

func (options jsonTagOptions) contains(name string) bool {
	remaining := string(options)
	for remaining != "" {
		var option string
		option, remaining, _ = strings.Cut(remaining, ",")
		if option == name {
			return true
		}
	}
	return false
}

type jsonPlannedField struct {
	name       string
	index      []int
	typeName   reflect.Type
	tagged     bool
	omitEmpty  bool
	omitZero   bool
	quoted     bool
	customZero bool
}

type jsonStructPlan struct {
	fields []jsonPlannedField
}

type jsonZeroer interface {
	IsZero() bool
}

var (
	jsonStructPlanCache sync.Map
	jsonZeroerType      = reflect.TypeOf((*jsonZeroer)(nil)).Elem()
)

func cachedJSONStructPlan(structType reflect.Type) jsonStructPlan {
	if cached, ok := jsonStructPlanCache.Load(structType); ok {
		return cached.(jsonStructPlan)
	}
	plan := buildJSONStructPlan(structType)
	actual, _ := jsonStructPlanCache.LoadOrStore(structType, plan)
	return actual.(jsonStructPlan)
}

// buildJSONStructPlan mirrors the field-selection rules of the Go 1.26
// encoding/json encoder pinned by go.mod, without copying its encoder machinery.
func buildJSONStructPlan(structType reflect.Type) jsonStructPlan {
	current := []jsonPlannedField{}
	next := []jsonPlannedField{{typeName: structType}}
	var currentCount map[reflect.Type]int
	visited := map[reflect.Type]bool{}
	fields := []jsonPlannedField{}

	for len(next) != 0 {
		current, next = next, current[:0]
		count := currentCount
		currentCount = map[reflect.Type]int{}
		for _, parent := range current {
			if visited[parent.typeName] {
				continue
			}
			visited[parent.typeName] = true
			for fieldIndex := 0; fieldIndex < parent.typeName.NumField(); fieldIndex++ {
				structField := parent.typeName.Field(fieldIndex)
				if structField.Anonymous {
					embeddedType := structField.Type
					if embeddedType.Kind() == reflect.Pointer {
						embeddedType = embeddedType.Elem()
					}
					if !structField.IsExported() && embeddedType.Kind() != reflect.Struct {
						continue
					}
				} else if !structField.IsExported() {
					continue
				}

				tag := structField.Tag.Get("json")
				if tag == "-" {
					continue
				}
				name, optionText, _ := strings.Cut(tag, ",")
				if !validJSONTagName(name) {
					name = ""
				}
				options := jsonTagOptions(optionText)
				index := append(append([]int(nil), parent.index...), fieldIndex)
				fieldType := structField.Type
				if fieldType.Name() == "" && fieldType.Kind() == reflect.Pointer {
					fieldType = fieldType.Elem()
				}
				quoted := false
				if options.contains("string") {
					switch fieldType.Kind() {
					case reflect.Bool,
						reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
						reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
						reflect.Float32, reflect.Float64, reflect.String:
						quoted = true
					}
				}

				if name != "" || !structField.Anonymous || fieldType.Kind() != reflect.Struct {
					tagged := name != ""
					if name == "" {
						name = structField.Name
					}
					planned := jsonPlannedField{
						name: name, index: index, typeName: fieldType, tagged: tagged,
						omitEmpty: options.contains("omitempty"), omitZero: options.contains("omitzero"), quoted: quoted,
					}
					planned.customZero = planned.omitZero && jsonFieldHasCustomZero(structField.Type)
					fields = append(fields, planned)
					if count[parent.typeName] > 1 {
						fields = append(fields, planned)
					}
					continue
				}

				currentCount[fieldType]++
				if currentCount[fieldType] == 1 {
					next = append(next, jsonPlannedField{name: fieldType.Name(), index: index, typeName: fieldType})
				}
			}
		}
	}

	slices.SortFunc(fields, compareJSONFieldsByName)
	selected := fields[:0]
	for start := 0; start < len(fields); {
		end := start + 1
		for end < len(fields) && fields[end].name == fields[start].name {
			end++
		}
		if dominant, ok := dominantJSONField(fields[start:end]); ok {
			selected = append(selected, dominant)
		}
		start = end
	}
	slices.SortFunc(selected, func(left, right jsonPlannedField) int {
		return slices.Compare(left.index, right.index)
	})
	return jsonStructPlan{fields: selected}
}

func compareJSONFieldsByName(left, right jsonPlannedField) int {
	if comparison := strings.Compare(left.name, right.name); comparison != 0 {
		return comparison
	}
	if len(left.index) < len(right.index) {
		return -1
	}
	if len(left.index) > len(right.index) {
		return 1
	}
	if left.tagged != right.tagged {
		if left.tagged {
			return -1
		}
		return 1
	}
	return slices.Compare(left.index, right.index)
}

func dominantJSONField(fields []jsonPlannedField) (jsonPlannedField, bool) {
	if len(fields) > 1 && len(fields[0].index) == len(fields[1].index) && fields[0].tagged == fields[1].tagged {
		return jsonPlannedField{}, false
	}
	return fields[0], true
}

func validJSONTagName(name string) bool {
	if name == "" {
		return false
	}
	for _, character := range name {
		switch {
		case strings.ContainsRune("!#$%&()*+-./:;<=>?@[]^_{|}~ ", character):
		case !unicode.IsLetter(character) && !unicode.IsDigit(character):
			return false
		}
	}
	return true
}

func jsonFieldHasCustomZero(fieldType reflect.Type) bool {
	switch {
	case fieldType.Kind() == reflect.Interface && fieldType.Implements(jsonZeroerType):
		return true
	case fieldType.Kind() == reflect.Pointer && fieldType.Implements(jsonZeroerType):
		return true
	case fieldType.Implements(jsonZeroerType):
		return true
	case reflect.PointerTo(fieldType).Implements(jsonZeroerType):
		return true
	default:
		return false
	}
}

func jsonPlannedFieldValue(root reflect.Value, field jsonPlannedField) (reflect.Value, bool) {
	value := root
	for _, index := range field.index {
		if value.Kind() == reflect.Pointer {
			if value.IsNil() {
				return reflect.Value{}, false
			}
			value = value.Elem()
		}
		value = value.Field(index)
	}
	return value, true
}

func omitJSONPlannedField(field jsonPlannedField, value reflect.Value) bool {
	if field.omitEmpty && emptyJSONValue(value) {
		return true
	}
	return field.omitZero && value.IsZero()
}

func emptyJSONValue(value reflect.Value) bool {
	switch value.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return value.Len() == 0
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64,
		reflect.Interface, reflect.Pointer:
		return value.IsZero()
	default:
		return false
	}
}
