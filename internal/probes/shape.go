package probes

import (
	"encoding/json"
	"fmt"
	"reflect"
)

// jsonShape reshapes upstream data into a CEL-friendly form: marshal to
// JSON, unmarshal to interface{}. The result is a tree of map[string]any /
// []any with snake_case keys driven by the upstream type's json tags, so
// rule conditions reference the same field names that appear in the
// pkg/types docs.
//
// A hand-rolled struct→map conversion would drift the moment a field is
// added upstream; a JSON round-trip is structurally locked to the
// upstream tags. The cost is one extra alloc per probe call, paid once
// per scan because the engine caches probe results per scan.
//
// Numeric fields decode as float64 — CEL's dyn type accepts that, but
// rules that compare with int literals should convert explicitly:
//
//	int(node.heap_max_bytes) <= 31 * 1024 * 1024 * 1024
//
// Nil slices anywhere in the tree are normalised to empty slices before
// marshal so CEL sees `[]` (size(...) == 0) rather than `null`. CEL
// rejects null when the variable is then dereferenced as a list, so
// without this normalisation a rule like
//
//	self.indices.all(idx, ...)
//
// would fail with "no such overload" against a fresh cluster whose
// /_recovery response carries indices=null.
func jsonShape(probeName string, v any) (any, error) {
	v = denilSlices(v)
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("%s probe: marshal: %w", probeName, err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%s probe: unmarshal: %w", probeName, err)
	}
	return out, nil
}

// denilSlices walks v and replaces every nil slice it finds with an
// empty slice of the same element type. Walks into struct fields,
// pointer targets, map values, and slice elements; stops at scalars.
//
// reflect.ValueOf(v) for an `any` parameter is not addressable, so we
// copy v into a fresh allocation (`addr.Elem()` IS addressable) and
// mutate that. This costs one extra alloc per probe call — paid once
// per scan because the engine caches probe results — and keeps the
// walker free to mutate struct fields in place.
func denilSlices(v any) any {
	if v == nil {
		return []any{}
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Slice && rv.IsNil() {
		return reflect.MakeSlice(rv.Type(), 0, 0).Interface()
	}
	addr := reflect.New(rv.Type())
	addr.Elem().Set(rv)
	denilValue(addr.Elem())
	return addr.Elem().Interface()
}

// denilValue is the recursive worker. It mutates rv in place when rv is
// addressable (the addr.Elem() copy from denilSlices is). For values
// reached through map indexing (which are NOT addressable), the
// map-walking branch builds an addressable temporary and writes back
// via SetMapIndex.
func denilValue(rv reflect.Value) {
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !rv.IsNil() {
			denilValue(rv.Elem())
		}
	case reflect.Struct:
		for i := 0; i < rv.NumField(); i++ {
			f := rv.Field(i)
			if !f.CanSet() {
				continue // unexported field — leave it alone
			}
			if f.Kind() == reflect.Slice && f.IsNil() {
				f.Set(reflect.MakeSlice(f.Type(), 0, 0))
				continue
			}
			denilValue(f)
		}
	case reflect.Slice:
		if rv.IsNil() {
			return // top-level nil slice is handled by the caller
		}
		for i := 0; i < rv.Len(); i++ {
			denilValue(rv.Index(i))
		}
	case reflect.Map:
		iter := rv.MapRange()
		for iter.Next() {
			val := iter.Value()
			if val.Kind() == reflect.Slice && val.IsNil() {
				rv.SetMapIndex(iter.Key(), reflect.MakeSlice(val.Type(), 0, 0))
				continue
			}
			// Map values are not addressable for nested mutation; copy
			// to an addressable temporary, mutate, write back.
			tmp := reflect.New(val.Type()).Elem()
			tmp.Set(val)
			denilValue(tmp)
			rv.SetMapIndex(iter.Key(), tmp)
		}
	}
}
