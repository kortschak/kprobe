// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package kprobe

import (
	"reflect"
	"strings"
	"testing"
)

var formatTests = []struct {
	name     string
	format   string
	wantName string
	wantID   int
	want     interface{}
}{
	{
		name: "https://www.kernel.org/doc/html/latest/trace/kprobetrace.html",
		format: `name: myprobe
ID: 780
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __probe_ip;	offset:12;	size:4;	signed:0;
	field:int __probe_nargs;	offset:16;	size:4;	signed:1;
	field:unsigned long dfd;	offset:20;	size:4;	signed:0;
	field:unsigned long filename;	offset:24;	size:4;	signed:0;
	field:unsigned long flags;	offset:28;	size:4;	signed:0;
	field:unsigned long mode;	offset:32;	size:4;	signed:0;


print fmt: "(%lx) dfd=%lx filename=%lx flags=%lx mode=%lx", REC->__probe_ip,
REC->dfd, REC->filename, REC->flags, REC->mode
`,
		wantName: "myprobe",
		wantID:   780,
		want: struct {
			Common_type          uint16 `ctyp:"unsigned short" json:"common_type"`
			Common_flags         uint8  `ctyp:"unsigned char" json:"common_flags"`
			Common_preempt_count uint8  `ctyp:"unsigned char" json:"common_preempt_count"`
			Common_pid           int32  `ctyp:"int" json:"common_pid"`
			_pad0                [4]uint8
			Probe_ip             uint32 `ctyp:"unsigned long" json:"__probe_ip"`
			Probe_nargs          int32  `ctyp:"int" json:"__probe_nargs"`
			Dfd                  uint32 `ctyp:"unsigned long" json:"dfd"`
			Filename             uint32 `ctyp:"unsigned long" json:"filename"`
			Flags                uint32 `ctyp:"unsigned long" json:"flags"`
			Mode                 uint32 `ctyp:"unsigned long" json:"mode"`
		}{},
	},
	{
		name: "https://www.kernel.org/doc/html/latest/trace/kprobetrace.html modified",
		format: `name: myprobe
ID: 780
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __probe_ip;	offset:12;	size:4;	signed:0;
	field:int __probe_nargs;	offset:16;	size:4;	signed:1;
	field:unsigned long dfd;	offset:20;	size:4;	signed:0;
	field:unsigned long filename;	offset:24;	size:4;	signed:0;
	field:unsigned long flags[2];	offset:28;	size:8;	signed:0;
	field:unsigned long mode;	offset:36;	size:4;	signed:0;


print fmt: "(%lx) dfd=%lx filename=%lx flags=%lx mode=%lx", REC->__probe_ip,
REC->dfd, REC->filename, REC->flags, REC->mode
`,
		wantName: "myprobe",
		wantID:   780,
		want: struct {
			Common_type          uint16 `ctyp:"unsigned short" json:"common_type"`
			Common_flags         uint8  `ctyp:"unsigned char" json:"common_flags"`
			Common_preempt_count uint8  `ctyp:"unsigned char" json:"common_preempt_count"`
			Common_pid           int32  `ctyp:"int" json:"common_pid"`
			_pad0                [4]uint8
			Probe_ip             uint32    `ctyp:"unsigned long" json:"__probe_ip"`
			Probe_nargs          int32     `ctyp:"int" json:"__probe_nargs"`
			Dfd                  uint32    `ctyp:"unsigned long" json:"dfd"`
			Filename             uint32    `ctyp:"unsigned long" json:"filename"`
			Flags                [2]uint32 `ctyp:"unsigned long[2]" json:"flags"`
			Mode                 uint32    `ctyp:"unsigned long" json:"mode"`
		}{},
	},
	{
		name: "https://lwn.net/Articles/748225/",
		format: `name: p_vfs_read_0
ID: 3842
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __probe_ip;	offset:8;	size:8;	signed:0;
	field:u64 arg1;	offset:16;	size:8;	signed:0;
	field:u8 arg2[8];	offset:24;	size:8;	signed:0;

print fmt: "(%lx) arg1=0x%Lx arg2={0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x}", REC->__probe_ip, REC->arg1, REC->arg2[0], REC->arg2[1], REC->arg2[2], REC->arg2[3], REC->arg2[4], REC->arg2[5], REC->arg2[6], REC->arg2[7]
`,
		wantName: "p_vfs_read_0",
		wantID:   3842,
		want: struct {
			Common_type          uint16   `ctyp:"unsigned short" json:"common_type"`
			Common_flags         uint8    `ctyp:"unsigned char" json:"common_flags"`
			Common_preempt_count uint8    `ctyp:"unsigned char" json:"common_preempt_count"`
			Common_pid           int32    `ctyp:"int" json:"common_pid"`
			Probe_ip             uint64   `ctyp:"unsigned long" json:"__probe_ip"`
			Arg1                 uint64   `ctyp:"u64" json:"arg1"`
			Arg2                 [8]uint8 `ctyp:"u8[8]" json:"arg2"`
		}{},
	},
}

func TestStruct(t *testing.T) {
	for _, test := range formatTests {
		typ, gotName, gotID, err := Struct(strings.NewReader(test.format))
		if err != nil {
			t.Errorf("unexpected error for %q: %v", test.name, err)
			continue
		}
		if gotName != test.wantName {
			t.Errorf("unexpected name for %q: got:%q want:%q",
				test.name, gotName, test.wantName)
		}
		if gotID != test.wantID {
			t.Errorf("unexpected ID for %q: got:%d want:%d",
				test.name, gotID, test.wantID)
		}

		wv := reflect.ValueOf(test.want)
		if !wv.CanConvert(typ) {
			t.Errorf("unexpected struct for %q:\ngot: %T\nwant:%T",
				test.name, reflect.New(typ).Elem().Interface(), test.want)
		}

		wt := wv.Type()
		for i := 0; i < wt.NumField(); i++ {
			if wt.Field(i).Tag != typ.Field(i).Tag {
				t.Errorf("unexpected struct tag for %q %s: got:%#q want:%#q",
					test.name, wt.Field(i).Name, typ.Field(i).Tag, wt.Field(i).Tag)
			}
		}
	}
}
