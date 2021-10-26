// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package kprobe provides a way to dynamically generate structs corresponding
// to linux kprobe event messages and deserialise message data.
package kprobe

import "C" // C imports is required for obtaining C type size information.

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
	"unicode"
	"unsafe"
)

// UnalignedFieldsError contains a list of field indexes for fields that are
// not aligned according to Go type alignment rules and are represented as byte
// arrays, or are part of a dynamic array.
type UnalignedFieldsError struct {
	// Fields and Unaligned describe unaligned fields in a kprobe struct.
	Fields    []int  // Fields is a list of unaligned fields.
	Unaligned []bool // Unaligned[i] is true for field i if it is unaligned.

	// DynamicArray indicates the struct has a __data_loc field.
	DynamicArray bool
}

func (e UnalignedFieldsError) Error() string {
	if len(e.Fields) == 0 && e.DynamicArray {
		return "dynamic array in struct"
	}
	if e.DynamicArray {
		return fmt.Sprintf("dynamic array and unaligned fields in struct: %d", e.Fields)
	}
	return fmt.Sprintf("unaligned fields in struct: %d", e.Fields)
}

// Struct returns a struct corresponding to the kprobe event format in r,
// along with the probe's name and id. See StructPkg for details. Padding
// fields use the kprobe package's package path.
func Struct(r io.Reader) (typ reflect.Type, name string, id uint16, size int, err error) {
	return StructPkg(r, pkgPath)
}

// pkgPath is the dynamically determined package path for this package.
var pkgPath = reflect.TypeOf(struct{ _ [0]byte }{}).Field(0).PkgPath

// Struct returns a struct corresponding to the kprobe event format in r,
// along with the probe's name and id. With padding fields using the package
// path, pkg. Struct attempts to construct the struct with the same types as
// specified by the event format, but in cases where this is not possible
// due to alignment, the unaligned fields will be represented as byte arrays
// of the same size and the field indices will be returned in an
// UnalignedFieldsError.
//
// C type information and the original C field names are included in struct
// field tags.
//
//  - ctyp: type information
//  - name: C field name
//  - unaligned: additional type information for packed fields.
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
func StructPkg(r io.Reader, pkg string) (typ reflect.Type, name string, id uint16, size int, err error) {
	var (
		fields    []reflect.StructField
		unaligned UnalignedFieldsError
	)
	sc := bufio.NewScanner(r)
	var i, padIdx, nextOffset int
	seen := make(map[string]bool)
	for sc.Scan() {
		b := sc.Bytes()
		switch {
		case bytes.HasPrefix(b, []byte("\tfield:")):
			f := strings.Split(strings.TrimPrefix(sc.Text(), "\t"), "\t")
			if len(f) != 4 {
				return nil, "", 0, 0, fmt.Errorf("invalid field line: %q", b)
			}
			ctyp, field, err := fieldName(f[0])
			if err != nil {
				return nil, "", 0, 0, err
			}
			if strings.HasPrefix(ctyp, "__data_loc") {
				unaligned.DynamicArray = true
			}
			offset, err := offset(f[1])
			if err != nil {
				return nil, "", 0, 0, err
			}
			typ, size, fallback, err := integerType(f[2], f[3], ctyp, offset, true)
			if err != nil {
				return nil, "", 0, 0, err
			}
			var tag reflect.StructTag
			if fallback {
				unaligned.Fields = append(unaligned.Fields, i+padIdx)
				tag = reflect.StructTag(fmt.Sprintf(`ctyp:%q name:%q unaligned:"%s %s"`,
					ctyp, field, f[2], f[3]))
			} else {
				tag = reflect.StructTag(fmt.Sprintf(`ctyp:%q name:%q`, ctyp, field))
			}
			pad := offset - nextOffset
			if pad < 0 {
				return nil, "", 0, 0, fmt.Errorf("invalid offset for field %d: %d", i, offset)
			}
			if pad > 0 {
				fields = append(fields, reflect.StructField{
					// TODO(kortschak): Use "_" in place of "_padN" when
					// go1.18 is the earliest supported Go version.
					// See https://golang.org/issue/49110.
					Name:    fmt.Sprintf("_pad%d", padIdx),
					PkgPath: pkg,
					Type:    reflect.ArrayOf(pad, reflect.TypeOf(uint8(0))),
					Offset:  uintptr(nextOffset),
				})
				padIdx++
			}
			fname := export(field)
			if seen[fname] {
				return nil, "", 0, 0, fmt.Errorf("duplicate field name: %s", fname)
			}
			seen[fname] = true
			fields = append(fields, reflect.StructField{
				Name:   fname,
				Type:   typ,
				Tag:    tag,
				Offset: uintptr(offset),
			})
			nextOffset = offset + size
			i++
		case bytes.HasPrefix(b, []byte("name: ")):
			name = string(bytes.TrimPrefix(b, []byte("name: ")))
		case bytes.HasPrefix(b, []byte("ID: ")):
			n, err := strconv.Atoi(strings.TrimPrefix(sc.Text(), "ID: "))
			if err != nil {
				return nil, "", 0, 0, err
			}
			if n > math.MaxUint16 {
				return nil, "", 0, 0, fmt.Errorf("format id overflows uint16: %d", n)
			}
			id = uint16(n)
		}
	}
	err = sc.Err()
	if err != nil {
		return nil, "", 0, 0, err
	}
	typ = reflect.StructOf(fields)
	for _, want := range fields {
		got, ok := typ.FieldByName(want.Name)
		if !ok {
			return nil, name, id, 0, fmt.Errorf("lost field %s", got.Name)
		}
		if got.Offset != want.Offset {
			return nil, name, id, 0, fmt.Errorf("could not generate correct field offset for %s: %d != %d", got.Name, got.Offset, want.Offset)
		}
	}
	if len(unaligned.Fields) != 0 || unaligned.DynamicArray {
		unaligned.Unaligned = make([]bool, len(fields))
		for _, i := range unaligned.Fields {
			unaligned.Unaligned[i] = true
		}
		err = unaligned
	}

	// We cannot use unsafe.Sizeof or reflect Type.Size to determine
	// the struct size because the finale field may be padded.
	size = nextOffset

	return typ, name, id, size, err
}

// UnpackedStructFor returns an unpacked struct type equivalent to typ, which must
// have been create with a call to Struct.
func UnpackedStructFor(typ reflect.Type) (reflect.Type, error) {
	fields := make([]reflect.StructField, typ.NumField())
	for i := range fields {
		f := typ.Field(i)
		if !f.IsExported() {
			if strings.HasPrefix(f.Name, "_pad") {
				f.Type = reflect.ArrayOf(0, reflect.TypeOf(uint8(0)))
			}
			fields[i] = f
			continue
		}

		if ctyp := f.Tag.Get("ctyp"); strings.HasPrefix(ctyp, "__data_loc") {
			typ, err := dynamicArray(strings.TrimPrefix(ctyp, "__data_loc "))
			if err != nil {
				return nil, err
			}
			f.Type = typ
			fields[i] = f
			continue
		}

		unaligned, ok := f.Tag.Lookup("unaligned")
		if !ok {
			fields[i] = f
			continue
		}
		tf := strings.Split(unaligned, " ")
		if len(tf) != 2 {
			return nil, fmt.Errorf("invalid unaligned tag syntax: %q", unaligned)
		}
		ctyp, ok := f.Tag.Lookup("ctyp")
		if !ok {
			return nil, fmt.Errorf("missing ctyp tag for unaligned field %s: %#q", f.Name, f.Tag)
		}
		var err error
		f.Type, _, _, err = integerType(tf[0], tf[1], ctyp, int(f.Offset), false)
		if err != nil {
			return nil, err
		}
		f.Tag = f.Tag[:strings.Index(string(f.Tag), " unaligned")]
		fields[i] = f
	}
	return reflect.StructOf(fields), nil
}

var machine binary.ByteOrder

func init() {
	order := [2]byte{0x1, 0x2}
	switch *(*uint16)(unsafe.Pointer(&order[0])) {
	case 0x0102:
		machine = binary.BigEndian
	case 0x0201:
		machine = binary.LittleEndian
	default:
		panic("invalid endianness")
	}
}

// Unpack makes of copy of src into dst adjusting the alignment of fields
// described in the provided unaligned fields error which should be obtained
// from a call to struct that generated the src type. The dst value must have
// been created using the type returned from UnpackedStructFor using the
// packed struct type as the input. The contents of data is the complete
// event message, required for unpacking dynamic array data. Dynamic arrays
// and strings do not have any terminating null bytes removed. If data is
// used during unpacking, the destination struct retains a reference to the
// memory in data.
func Unpack(dst, src reflect.Value, unaligned UnalignedFieldsError, data []byte) error {
	if !isStructPointer(dst) {
		return fmt.Errorf("invalid type: %T", dst)
	}
	if !isStructPointer(src) {
		return fmt.Errorf("invalid type: %T", src)
	}
	dst = dst.Elem()
	nDst := dst.NumField()
	src = src.Elem()
	nSrc := src.NumField()
	if nDst != nSrc {
		return fmt.Errorf("mismatched field count: %d != %d", nDst, nSrc)
	}
	if unaligned.Unaligned != nil && len(unaligned.Unaligned) != nDst {
		return fmt.Errorf("mismatched unaligned field count: %d != %d", len(unaligned.Unaligned), nDst)
	}
	dstTyp := dst.Type()
	srcTyp := src.Type()
	for i := 0; i < nDst; i++ {
		if unaligned.Unaligned != nil && unaligned.Unaligned[i] {
			continue
		}
		if !dstTyp.Field(i).IsExported() || !srcTyp.Field(i).IsExported() {
			continue
		}
		if ctyp := srcTyp.Field(i).Tag.Get("ctyp"); strings.HasPrefix(ctyp, "__data_loc") {
			typ := srcTyp.Field(i).Type
			if typ.Kind() != reflect.Uint32 {
				return fmt.Errorf("invalid type for dynamic array: %s", typ)
			}
			v := src.Field(i).Uint()
			off := int(v & 0xffff)
			n := int(v >> 16)
			if off > len(data) || off+n > len(data) {
				return fmt.Errorf("invalid dynamic data indexes: offset=%d len=%d", off, n)
			}
			data := data[off:]
			if len(data) == 0 {
				continue
			}
			class := dynamicArrayTypes[strings.TrimPrefix(ctyp, "__data_loc ")]
			if class.signed {
				switch class.size {
				case 1:
					s8 := unsafe.Slice((*int8)(unsafe.Pointer(&data[0])), n)
					dst.Field(i).Set(reflect.ValueOf(s8))
				case 2:
					s16 := unsafe.Slice((*int16)(unsafe.Pointer(&data[0])), n/2)
					dst.Field(i).Set(reflect.ValueOf(s16))
				case 4:
					s32 := unsafe.Slice((*uint32)(unsafe.Pointer(&data[0])), n/4)
					dst.Field(i).Set(reflect.ValueOf(s32))
				case 8:
					s64 := unsafe.Slice((*uint64)(unsafe.Pointer(&data[0])), n/8)
					dst.Field(i).Set(reflect.ValueOf(s64))
				default:
					panic(fmt.Sprintf("invalid typeclass size: %d", class.size))
				}
			} else {
				switch class.size {
				case 1:
					dst.Field(i).SetBytes(data[:n])
				case 2:
					u16 := unsafe.Slice((*uint16)(unsafe.Pointer(&data[0])), n/2)
					dst.Field(i).Set(reflect.ValueOf(u16))
				case 4:
					u32 := unsafe.Slice((*uint32)(unsafe.Pointer(&data[0])), n/4)
					dst.Field(i).Set(reflect.ValueOf(u32))
				case 8:
					u64 := unsafe.Slice((*uint64)(unsafe.Pointer(&data[0])), n/8)
					dst.Field(i).Set(reflect.ValueOf(u64))
				default:
					panic(fmt.Sprintf("invalid typeclass size: %d", class.size))
				}
			}
			continue
		}
		if !src.Field(i).Type().AssignableTo(dst.Field(i).Type()) {
			return fmt.Errorf("mismatched type for field %d: %s != %s", i, dst.Field(i).Type(), src.Field(i).Type())
		}
		dst.Field(i).Set(src.Field(i))
	}
	for _, u := range unaligned.Fields {
		dstU := dst.Field(u)
		dstSize := dstU.Type().Size()
		srcU := src.Field(u)
		srcSize := srcU.Type().Size()
		if dstSize != srcSize {
			return fmt.Errorf("mismatched size for field %d: %d != %d", u, dstSize, srcSize)
		}
		srcIface := srcU.Interface()
		var val uint64
		switch dstU.Kind() {
		case reflect.Uint16, reflect.Uint32, reflect.Uint64:
			switch srcSize {
			case 2:
				b := srcIface.([2]byte)
				val = uint64(machine.Uint16(b[:]))
			case 4:
				b := srcIface.([4]byte)
				val = uint64(machine.Uint32(b[:]))
			case 8:
				b := srcIface.([8]byte)
				val = machine.Uint64(b[:])
			}
			dstU.SetUint(val)
		case reflect.Int16, reflect.Int32, reflect.Int64:
			switch srcSize {
			case 2:
				b := srcIface.([2]byte)
				val = uint64(machine.Uint16(b[:]))
			case 4:
				b := srcIface.([4]byte)
				val = uint64(machine.Uint32(b[:]))
			case 8:
				b := srcIface.([8]byte)
				val = machine.Uint64(b[:])
			}
			dstU.SetInt(int64(val))
		default:
			return fmt.Errorf("invalid kind for field %d: %v", u, dstU.Kind())
		}
	}
	return nil
}

func isStructPointer(v reflect.Value) bool {
	return v.Kind() == reflect.Ptr && v.Elem().Kind() == reflect.Struct
}

// dynamicArray returns a []T corresponding to the given ctyp[]. ctyp is expected
// to be just the C type, without the __data_loc prefix.
func dynamicArray(ctyp string) (reflect.Type, error) {
	class, ok := dynamicArrayTypes[strings.TrimLeft(ctyp, "_")]
	if !ok {
		return nil, fmt.Errorf("unsupported dynamic array element type: %s", ctyp)
	}
	return reflect.SliceOf(integerTypes[class]), nil
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
	return string(lead)
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
// If the alignment of the resulting type is inconsistent with the provided
// offset and aligned is true, a byte array of the same length is constructed
// and fallback is returned true.
func integerType(size, signed, ctyp string, offset int, aligned bool) (typ reflect.Type, bytes int, fallback bool, err error) {
	size = strings.TrimPrefix(size, "size:")
	size = strings.TrimSuffix(size, ";")
	bytes, err = strconv.Atoi(size)
	if err != nil {
		return nil, 0, false, fmt.Errorf("invalid size: %w", err)
	}
	signed = strings.TrimPrefix(signed, "signed:")
	signed = strings.TrimSuffix(signed, ";")
	s, err := strconv.Atoi(signed)
	if err != nil {
		return nil, 0, false, fmt.Errorf("invalid size: %w", err)
	}
	n, dynamic, err := arraySize(ctyp)
	if err != nil {
		return nil, 0, false, err
	}
	if bytes%n != 0 {
		return nil, 0, false, fmt.Errorf("invalid size for array: size=%d elements=%d", bytes, n)
	}
	typ = integerTypes[typeClass{bytes / n, s == 1 && !dynamic}]
	if aligned && offset%typ.Align() != 0 {
		return reflect.ArrayOf(bytes, integerTypes[typeClass{1, false}]), bytes, true, nil
	}
	if n > 1 {
		typ = reflect.ArrayOf(n, typ)
	}
	return typ, bytes, false, nil
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

var dynamicArrayTypes = map[string]typeClass{
	"char[]":  {int(unsafe.Sizeof(C.char(0))), false}, // Special case char to uint8.
	"schar[]": {int(unsafe.Sizeof(C.schar(0))), true},
	"uchar[]": {int(unsafe.Sizeof(C.uchar(0))), false},

	"short[]":          {int(unsafe.Sizeof(C.short(0))), true},
	"signed short[]":   {int(unsafe.Sizeof(C.short(0))), true},
	"unsigned short[]": {int(unsafe.Sizeof(C.ushort(0))), false},

	"long[]":          {int(unsafe.Sizeof(C.long(0))), true},
	"signed long[]":   {int(unsafe.Sizeof(C.long(0))), true},
	"unsigned long[]": {int(unsafe.Sizeof(C.ulong(0))), false},

	"long long[]":          {int(unsafe.Sizeof(C.longlong(0))), true},
	"signed long long[]":   {int(unsafe.Sizeof(C.longlong(0))), true},
	"unsigned long long[]": {int(unsafe.Sizeof(C.ulonglong(0))), false},

	"s8[]":  {1, true},
	"s16[]": {2, true},
	"s32[]": {4, true},
	"s64[]": {8, true},

	"u8[]":  {1, false},
	"u16[]": {2, false},
	"u32[]": {4, false},
	"u64[]": {8, false},
}
