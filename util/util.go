package util

import (
	"fmt"
	rf "reflect"
)

// Retrieves obj's deepest value traversing pointers.
func AsValue(obj interface{}) rf.Value {
	v := rf.ValueOf(obj)
	for v.CanInterface() && v.Kind() == rf.Ptr {
		v = v.Elem()
	}
	return v
}

type Branch = map[string]interface{}

/**
 * Compares the two objects fieldwise.
 * lhs and rhs should be of the same struct type (or pointers (to pointers...) to one).
 * Fields are either strings that are exported field names, or maps of string to empty interfaces (the type Branch above) for comparing struct-typed fields.
 *
 * In the latter case, for each map element its key should be a name of an exported struct field, and its value can be either:
 *   - a string - for a single nested struct field of a comparable type
 *   - a branch - for a single nested struct field which in turn is again a nested struct
 *   - a slice of strings     - for a few nested struct fields of comparable types
 *   - a slice of interface{} - each one is either a string or a Branch
 *
 * Panics if a field selector is of some other type.
 *
 * Example:
 *
type T struct {
	A float64, B string
}

type S struct {
	X int, Y T, Z string
}

a := S{
	X: 42,
	Y: T{
		A: 3.14,
		B: "Hi!"
	},
	Z: "ignored",
}

b := S{
	X: 42,
	Y: T{
		A: 3.14,
		B: "Lo.",
	},
	Z: "unused",
}

// only a.X and b.X,
// and a.Y.A and b.Y.A are compared
FieldwiseEqual(a, b, "X", Branch{ "Y": "A" })                --> true

// only a.X and b.X,
// and a.Y.A and b.Y.A,
// and a.Y.B and b.Y.B are compared
FieldwiseEqual(a, b, "X", Branch{ "Y": []string{"A", "B"} }) --> false

*/

func FieldwiseEqual(lhs interface{}, rhs interface{}, fields ...interface{}) bool {
	l := AsValue(lhs)
	r := AsValue(rhs)
	return fieldwiseEqual(l, r, fields...)

func fieldwiseEqual(l rf.Value, r rf.Value, fields ...interface{}) bool {
	if !l.CanInterface() {
		return !r.CanInterface()
	}
	if !r.CanInterface() {
		return false
	}
	for _, field := range fields {
		switch selector := field.(type) {

		case string:
			lfield := l.FieldByName(selector)
			rfield := r.FieldByName(selector)
			if !lfield.CanInterface() || !rfield.CanInterface() || lfield.Interface() != rfield.Interface() {
				return false
			}

		case Branch:
			for id, subpath := range selector {
				lfield := l.FieldByName(id)
				rfield := r.FieldByName(id)
				if !lfield.CanInterface() || !rfield.CanInterface() {
					return false
				}

				var matches bool
				switch branch := subpath.(type) {
				case []string:
					interfaces := make([]interface{}, len(branch))
					for i, v := range branch {
						interfaces[i] = v
					}
					matches = fieldwiseEqual(lfield, rfield, interfaces...)

				case []interface{}:
					matches = fieldwiseEqual(lfield, rfield, branch...)

				default:
					matches = fieldwiseEqual(lfield, rfield, branch)
				}

				if !matches {
					return false
				}
			}

		default:
			panic(fmt.Sprintf("FieldwiseEqual: invalid field selector +%v", field))
		}
	}
	return true
}
