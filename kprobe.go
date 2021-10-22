// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package kprobe provides a way to dynmically generate structs corresponding
// to linux kprobe event messages.
package kprobe

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode"
)

// Struct returns a struct corresponding to the kprobe event format in r,
// along with the probe's name and id.
//
// Structs referencing dynamic arrays as string data hold a 32 bit unsigned
// value that points to the data with a ctyp field tag with the prefix
// __data_loc. The value has the following semantics:
//
//   #define __get_dynamic_array(field)
//     ((void *)__entry + (__entry->__data_loc_##field & 0xffff))
//
//   #define __get_dynamic_array_len(field)
//     ((__entry->__data_loc_##field >> 16) & 0xffff)
//
func Struct(r io.Reader) (typ reflect.Type, name string, id int, err error) {
	var fields []reflect.StructField
	sc := bufio.NewScanner(r)
	var i, nextOffset int
	for sc.Scan() {
		b := sc.Bytes()
		switch {
		case bytes.HasPrefix(b, []byte("\tfield:")):
			f := strings.Split(strings.TrimPrefix(sc.Text(), "\t"), "\t")
			if len(f) != 4 {
				return nil, "", 0, fmt.Errorf("invalid field line: %q", b)
			}
			ctyp, field, err := fieldName(f[0])
			if err != nil {
				return nil, "", 0, err
			}
			offset, err := offset(f[1])
			if err != nil {
				return nil, "", 0, err
			}
			typ, size, err := integerType(f[2], f[3], ctyp)
			if err != nil {
				return nil, "", 0, err
			}
			pad := offset - nextOffset
			if pad < 0 {
				panic(fmt.Sprintf("invalid padding: %d", pad))
			}
			if pad > 0 {
				fields = append(fields, reflect.StructField{
					Name:    fmt.Sprintf("_pad%d", i),
					PkgPath: "github.com/kortschak/kprobe", // Needed for testing.
					Type:    reflect.ArrayOf(pad, reflect.TypeOf(uint8(0))),
					Offset:  uintptr(nextOffset),
				})
				i++
			}
			fields = append(fields, reflect.StructField{
				Name:   export(field),
				Type:   typ,
				Tag:    reflect.StructTag(fmt.Sprintf(`ctyp:%q json:%q`, ctyp, field)),
				Offset: uintptr(offset),
			})
			nextOffset = offset + size
		case bytes.HasPrefix(b, []byte("name: ")):
			name = string(bytes.TrimPrefix(b, []byte("name: ")))
		case bytes.HasPrefix(b, []byte("ID: ")):
			id, err = strconv.Atoi(strings.TrimPrefix(sc.Text(), "ID: "))
			if err != nil {
				return nil, "", 0, err
			}
		}
	}
	err = sc.Err()
	if err != nil {
		return nil, "", 0, err
	}
	typ = reflect.StructOf(fields)
	for _, want := range fields {
		got, ok := typ.FieldByName(want.Name)
		if !ok {
			return nil, name, id, fmt.Errorf("lost field %s", got.Name)
		}
		if got.Offset != want.Offset {
			return nil, name, id, fmt.Errorf("could not generate correct field offset for %s: %d != %d", got.Name, got.Offset, want.Offset)
		}
	}
	return typ, name, id, nil
}

// export converts a string to an exported Go label.
func export(s string) string {
	n := strings.TrimLeft(s, "_")
	if n == "" {
		return s
	}
	var lead rune
	for i, r := range n {
		if i == 0 {
			if unicode.IsUpper(r) {
				return n
			}
			lead = unicode.ToUpper(r)
		} else {
			return string(lead) + n[i:]
		}
	}
	panic("cannot reach")
}

// fieldName parses the C type and field name from the provided string.
func fieldName(s string) (ctyp, field string, err error) {
	s = strings.TrimPrefix(s, "field:")
	s = strings.TrimSuffix(s, ";")
	i := strings.LastIndex(s, " ")
	if i < 0 {
		return "", "", fmt.Errorf("invalid field description: %q", s)
	}
	ctyp = s[:i]
	field = s[i+1:]
	if idx := strings.Index(field, "["); idx >= 0 {
		ctyp += field[idx:]
		field = field[:idx]
	}
	return ctyp, field, nil
}

// offset parses the offset field from a kprobe format description.
func offset(s string) (int, error) {
	s = strings.TrimPrefix(s, "offset:")
	s = strings.TrimSuffix(s, ";")
	return strconv.Atoi(s)
}

// integerType returns a Go type corresponding to the type specified in a
// kprobe format based on the size and signed fields and the array spec in
// the field field, according to https://www.kernel.org/doc/html/latest/trace/kprobetrace.html.
func integerType(size, signed, ctyp string) (reflect.Type, int, error) {
	size = strings.TrimPrefix(size, "size:")
	size = strings.TrimSuffix(size, ";")
	bytes, err := strconv.Atoi(size)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid size: %w", err)
	}
	signed = strings.TrimPrefix(signed, "signed:")
	signed = strings.TrimSuffix(signed, ";")
	s, err := strconv.Atoi(signed)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid size: %w", err)
	}
	n, dynamic, err := arraySize(ctyp)
	if err != nil {
		return nil, 0, err
	}
	if bytes%n != 0 {
		return nil, 0, fmt.Errorf("invalid size for array: size=%d elements=%d", bytes, n)
	}
	typ := integerTypes[typeClass{bytes / n, s == 1 && !dynamic}]
	if n > 1 {
		typ = reflect.ArrayOf(n, typ)
	}
	return typ, bytes, nil
}

// arraySize returns the number of elements in an array according to the syntax
// specified in the kprobetrace documentation.
func arraySize(ctyp string) (n int, dynamic bool, err error) {
	if !strings.HasSuffix(ctyp, "]") {
		return 1, false, nil
	}
	prefix := strings.TrimRightFunc(ctyp[:len(ctyp)-1], func(r rune) bool {
		return '0' <= r && r <= '9'
	})
	if !strings.HasSuffix(prefix, "[") {
		return 0, false, fmt.Errorf("invalid data type: %q", ctyp)
	}
	c := strings.TrimPrefix(ctyp[:len(ctyp)-1], prefix)
	if c == "" {
		if !strings.HasPrefix(ctyp, "__data_loc ") {
			return 0, false, fmt.Errorf("invalid data type: %q", ctyp)
		}
		// We are a dynamic array.
		return 1, true, nil
	}
	n, err = strconv.Atoi(c)
	return n, false, err
}

type typeClass struct {
	size   int
	signed bool
}

var integerTypes = map[typeClass]reflect.Type{
	{1, true}: reflect.TypeOf(int8(0)),
	{2, true}: reflect.TypeOf(int16(0)),
	{4, true}: reflect.TypeOf(int32(0)),
	{8, true}: reflect.TypeOf(int64(0)),

	{1, false}: reflect.TypeOf(uint8(0)),
	{2, false}: reflect.TypeOf(uint16(0)),
	{4, false}: reflect.TypeOf(uint32(0)),
	{8, false}: reflect.TypeOf(uint64(0)),
}
