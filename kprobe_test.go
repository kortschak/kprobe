// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package kprobe

import (
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

var formatTests = []struct {
	name          string
	format        string
	wantName      string
	wantID        int
	wantAligned   interface{}
	wantUnaligned interface{}
	wantErr       error
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
		wantAligned: struct {
			Common_type          uint16 `ctyp:"unsigned short" name:"common_type"`
			Common_flags         uint8  `ctyp:"unsigned char" name:"common_flags"`
			Common_preempt_count uint8  `ctyp:"unsigned char" name:"common_preempt_count"`
			Common_pid           int32  `ctyp:"int" name:"common_pid"`
			_pad0                [4]uint8
			Probe_ip             uint32 `ctyp:"unsigned long" name:"__probe_ip"`
			Probe_nargs          int32  `ctyp:"int" name:"__probe_nargs"`
			Dfd                  uint32 `ctyp:"unsigned long" name:"dfd"`
			Filename             uint32 `ctyp:"unsigned long" name:"filename"`
			Flags                uint32 `ctyp:"unsigned long" name:"flags"`
			Mode                 uint32 `ctyp:"unsigned long" name:"mode"`
		}{},
		wantUnaligned: struct {
			Common_type          uint16 `ctyp:"unsigned short" name:"common_type"`
			Common_flags         uint8  `ctyp:"unsigned char" name:"common_flags"`
			Common_preempt_count uint8  `ctyp:"unsigned char" name:"common_preempt_count"`
			Common_pid           int32  `ctyp:"int" name:"common_pid"`
			_pad0                [0]uint8
			Probe_ip             uint32 `ctyp:"unsigned long" name:"__probe_ip"`
			Probe_nargs          int32  `ctyp:"int" name:"__probe_nargs"`
			Dfd                  uint32 `ctyp:"unsigned long" name:"dfd"`
			Filename             uint32 `ctyp:"unsigned long" name:"filename"`
			Flags                uint32 `ctyp:"unsigned long" name:"flags"`
			Mode                 uint32 `ctyp:"unsigned long" name:"mode"`
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
		wantAligned: struct {
			Common_type          uint16 `ctyp:"unsigned short" name:"common_type"`
			Common_flags         uint8  `ctyp:"unsigned char" name:"common_flags"`
			Common_preempt_count uint8  `ctyp:"unsigned char" name:"common_preempt_count"`
			Common_pid           int32  `ctyp:"int" name:"common_pid"`
			_pad0                [4]uint8
			Probe_ip             uint32    `ctyp:"unsigned long" name:"__probe_ip"`
			Probe_nargs          int32     `ctyp:"int" name:"__probe_nargs"`
			Dfd                  uint32    `ctyp:"unsigned long" name:"dfd"`
			Filename             uint32    `ctyp:"unsigned long" name:"filename"`
			Flags                [2]uint32 `ctyp:"unsigned long[2]" name:"flags"`
			Mode                 uint32    `ctyp:"unsigned long" name:"mode"`
		}{},
		wantUnaligned: struct {
			Common_type          uint16 `ctyp:"unsigned short" name:"common_type"`
			Common_flags         uint8  `ctyp:"unsigned char" name:"common_flags"`
			Common_preempt_count uint8  `ctyp:"unsigned char" name:"common_preempt_count"`
			Common_pid           int32  `ctyp:"int" name:"common_pid"`
			_pad0                [0]uint8
			Probe_ip             uint32    `ctyp:"unsigned long" name:"__probe_ip"`
			Probe_nargs          int32     `ctyp:"int" name:"__probe_nargs"`
			Dfd                  uint32    `ctyp:"unsigned long" name:"dfd"`
			Filename             uint32    `ctyp:"unsigned long" name:"filename"`
			Flags                [2]uint32 `ctyp:"unsigned long[2]" name:"flags"`
			Mode                 uint32    `ctyp:"unsigned long" name:"mode"`
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
		wantAligned: struct {
			Common_type          uint16   `ctyp:"unsigned short" name:"common_type"`
			Common_flags         uint8    `ctyp:"unsigned char" name:"common_flags"`
			Common_preempt_count uint8    `ctyp:"unsigned char" name:"common_preempt_count"`
			Common_pid           int32    `ctyp:"int" name:"common_pid"`
			Probe_ip             uint64   `ctyp:"unsigned long" name:"__probe_ip"`
			Arg1                 uint64   `ctyp:"u64" name:"arg1"`
			Arg2                 [8]uint8 `ctyp:"u8[8]" name:"arg2"`
		}{},
		wantUnaligned: struct {
			Common_type          uint16   `ctyp:"unsigned short" name:"common_type"`
			Common_flags         uint8    `ctyp:"unsigned char" name:"common_flags"`
			Common_preempt_count uint8    `ctyp:"unsigned char" name:"common_preempt_count"`
			Common_pid           int32    `ctyp:"int" name:"common_pid"`
			Probe_ip             uint64   `ctyp:"unsigned long" name:"__probe_ip"`
			Arg1                 uint64   `ctyp:"u64" name:"arg1"`
			Arg2                 [8]uint8 `ctyp:"u8[8]" name:"arg2"`
		}{},
	},
	{
		name: "ath10k_htt_stats",
		format: `name: ath10k_htt_stats
ID: 2059
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:__data_loc char[] device;	offset:8;	size:4;	signed:1;
	field:__data_loc char[] driver;	offset:12;	size:4;	signed:1;
	field:size_t buf_len;	offset:16;	size:8;	signed:0;
	field:__data_loc u8[] buf;	offset:24;	size:4;	signed:0;

print fmt: "%s %s len %zu", __get_str(driver), __get_str(device), REC->buf_len
`,
		wantName: "ath10k_htt_stats",
		wantID:   2059,
		wantAligned: struct {
			Common_type          uint16 `ctyp:"unsigned short" name:"common_type"`
			Common_flags         uint8  `ctyp:"unsigned char" name:"common_flags"`
			Common_preempt_count uint8  `ctyp:"unsigned char" name:"common_preempt_count"`
			Common_pid           int32  `ctyp:"int" name:"common_pid"`
			Device               uint32 `ctyp:"__data_loc char[]" name:"device"`
			Driver               uint32 `ctyp:"__data_loc char[]" name:"driver"`
			Buf_len              uint64 `ctyp:"size_t" name:"buf_len"`
			Buf                  uint32 `ctyp:"__data_loc u8[]" name:"buf"`
		}{},
		wantUnaligned: struct {
			Common_type          uint16 `ctyp:"unsigned short" name:"common_type"`
			Common_flags         uint8  `ctyp:"unsigned char" name:"common_flags"`
			Common_preempt_count uint8  `ctyp:"unsigned char" name:"common_preempt_count"`
			Common_pid           int32  `ctyp:"int" name:"common_pid"`
			Device               []byte `ctyp:"__data_loc char[]" name:"device"`
			Driver               []byte `ctyp:"__data_loc char[]" name:"driver"`
			Buf_len              uint64 `ctyp:"size_t" name:"buf_len"`
			Buf                  []byte `ctyp:"__data_loc u8[]" name:"buf"`
		}{},
	},
	{
		name: "ip_local_out_call",
		format: `name: ip_local_out_call
ID: 3226
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __probe_ip;	offset:8;	size:8;	signed:0;
	field:u64 sock;	offset:16;	size:8;	signed:0;
	field:u32 size;	offset:24;	size:4;	signed:0;
	field:u16 af;	offset:28;	size:2;	signed:0;
	field:u32 laddr;	offset:30;	size:4;	signed:0;
	field:u16 lport;	offset:34;	size:2;	signed:0;
	field:u32 raddr;	offset:36;	size:4;	signed:0;
	field:u16 rport;	offset:40;	size:2;	signed:0;

print fmt: "(%lx) sock=0x%Lx size=%u af=%u laddr=%u lport=%u raddr=%u rport=%u", REC->__probe_ip, REC->sock, REC->size, REC->af, REC->laddr, REC->lport, REC->raddr, REC->rport
`,
		wantName: "ip_local_out_call",
		wantID:   3226,
		wantAligned: struct {
			Common_type          uint16   `ctyp:"unsigned short" name:"common_type"`
			Common_flags         uint8    `ctyp:"unsigned char" name:"common_flags"`
			Common_preempt_count uint8    `ctyp:"unsigned char" name:"common_preempt_count"`
			Common_pid           int32    `ctyp:"int" name:"common_pid"`
			Probe_ip             uint64   `ctyp:"unsigned long" name:"__probe_ip"`
			Sock                 uint64   `ctyp:"u64" name:"sock"`
			Size                 uint32   `ctyp:"u32" name:"size"`
			Af                   uint16   `ctyp:"u16" name:"af"`
			Laddr                [4]uint8 `ctyp:"u32" name:"laddr" unaligned:"size:4; signed:0;"`
			Lport                uint16   `ctyp:"u16" name:"lport"`
			Raddr                uint32   `ctyp:"u32" name:"raddr"`
			Rport                uint16   `ctyp:"u16" name:"rport"`
		}{},
		wantUnaligned: struct {
			Common_type          uint16 `ctyp:"unsigned short" name:"common_type"`
			Common_flags         uint8  `ctyp:"unsigned char" name:"common_flags"`
			Common_preempt_count uint8  `ctyp:"unsigned char" name:"common_preempt_count"`
			Common_pid           int32  `ctyp:"int" name:"common_pid"`
			Probe_ip             uint64 `ctyp:"unsigned long" name:"__probe_ip"`
			Sock                 uint64 `ctyp:"u64" name:"sock"`
			Size                 uint32 `ctyp:"u32" name:"size"`
			Af                   uint16 `ctyp:"u16" name:"af"`
			Laddr                uint32 `ctyp:"u32" name:"laddr"`
			Lport                uint16 `ctyp:"u16" name:"lport"`
			Raddr                uint32 `ctyp:"u32" name:"raddr"`
			Rport                uint16 `ctyp:"u16" name:"rport"`
		}{},
		wantErr: UnalignedFieldsError{
			Fields:    []int{8},
			Unaligned: []bool{8: true, 11: false},
		},
	},
	{
		name: "do_sys_open",
		format: `name: do_sys_open
ID: 656
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:__data_loc char[] filename;	offset:8;	size:4;	signed:1;
	field:int flags;	offset:12;	size:4;	signed:1;
	field:int mode;	offset:16;	size:4;	signed:1;

print fmt: ""%s" %x %o", __get_str(filename), REC->flags, REC->mode
`,
		wantName: "do_sys_open",
		wantID:   656,
		wantAligned: struct {
			Common_type          uint16 `ctyp:"unsigned short" name:"common_type"`
			Common_flags         uint8  `ctyp:"unsigned char" name:"common_flags"`
			Common_preempt_count uint8  `ctyp:"unsigned char" name:"common_preempt_count"`
			Common_pid           int32  `ctyp:"int" name:"common_pid"`
			Filename             uint32 `ctyp:"__data_loc char[]" name:"filename"`
			Flags                int32  `ctyp:"int" name:"flags"`
			Mode                 int32  `ctyp:"int" name:"mode"`
		}{},
		wantUnaligned: struct {
			Common_type          uint16  `ctyp:"unsigned short" name:"common_type"`
			Common_flags         uint8   `ctyp:"unsigned char" name:"common_flags"`
			Common_preempt_count uint8   `ctyp:"unsigned char" name:"common_preempt_count"`
			Common_pid           int32   `ctyp:"int" name:"common_pid"`
			Filename             []uint8 `ctyp:"__data_loc char[]" name:"filename"`
			Flags                int32   `ctyp:"int" name:"flags"`
			Mode                 int32   `ctyp:"int" name:"mode"`
		}{},
		wantErr: nil,
	},
}

func TestStruct(t *testing.T) {
	for _, test := range formatTests {
		typAligned, gotName, gotID, err := Struct(strings.NewReader(test.format))
		if !reflect.DeepEqual(err, test.wantErr) {
			t.Errorf("unexpected error for aligned %q: got:%#v want:%#v",
				test.name, err, test.wantErr)
			if test.wantErr == nil {
				continue
			}
		}
		if gotName != test.wantName {
			t.Errorf("unexpected name for %q: got:%q want:%q",
				test.name, gotName, test.wantName)
		}
		if gotID != test.wantID {
			t.Errorf("unexpected ID for %q: got:%d want:%d",
				test.name, gotID, test.wantID)
		}
		checkStruct(t, test.name, typAligned, test.wantAligned)

		typUnaligned, err := UnpackedStructFor(typAligned)
		if err != nil {
			t.Errorf("unexpected error for unaligned from type %q: got:%#v want:%#v",
				test.name, err, test.wantErr)
			continue
		}
		checkStruct(t, test.name, typUnaligned, test.wantUnaligned)
	}
}

func checkStruct(t *testing.T, name string, got reflect.Type, want interface{}) {
	t.Helper()

	wv := reflect.ValueOf(want)
	if !wv.CanConvert(got) {
		t.Errorf("unexpected struct for %q:\ngot: %T\nwant:%T",
			name, reflect.New(got).Elem().Interface(), want)
	}

	wt := wv.Type()
	for i := 0; i < wt.NumField(); i++ {
		if wt.Field(i).Tag != got.Field(i).Tag {
			t.Errorf("unexpected struct tag for %q %s: got:%#q want:%#q",
				name, wt.Field(i).Name, got.Field(i).Tag, wt.Field(i).Tag)
		}
	}
}

var unpackTests = []struct {
	name   string
	format string
	data   []byte
	want   interface{}
}{
	{
		name: "do_sys_open",
		format: `name: do_sys_open_test
ID: 7021
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:unsigned long __probe_ip;	offset:8;	size:8;	signed:0;
	field:u32 dfd;	offset:16;	size:4;	signed:0;
	field:__data_loc char[] filename;	offset:20;	size:4;	signed:1;
	field:u32 flags;	offset:24;	size:4;	signed:0;
	field:u32 mode;	offset:28;	size:4;	signed:0;
`,
		data: []byte{
			0xb2, 0x1b, 0x00, 0x00, 0xc1, 0x7f, 0x00, 0x00,
			0xf0, 0xa1, 0x6d, 0xae, 0xff, 0xff, 0xff, 0xff,
			0x30, 0xa5, 0x6d, 0xae, 0x20, 0x00, 0x0a, 0x00,
			0x41, 0x82, 0x08, 0x00, 0xa4, 0x01, 0x00, 0x00,
			0x66, 0x69, 0x6c, 0x65, 0x2e, 0x74, 0x65, 0x78,
			0x74, 0x00, 0x00, 0x00,
		},
		want: struct {
			Common_type          uint16  `ctyp:"unsigned short" name:"common_type"`
			Common_flags         uint8   `ctyp:"unsigned char" name:"common_flags"`
			Common_preempt_count uint8   `ctyp:"unsigned char" name:"common_preempt_count"`
			Common_pid           int32   `ctyp:"int" name:"common_pid"`
			Probe_ip             uint64  `ctyp:"unsigned long" name:"__probe_ip"`
			Dfd                  uint32  `ctyp:"u32" name:"dfd"`
			Filename             []uint8 `ctyp:"__data_loc char[]" name:"filename"`
			Flags                uint32  `ctyp:"u32" name:"flags"`
			Mode                 uint32  `ctyp:"u32" name:"mode"`
		}{Common_type: 0x1bb2,
			Common_flags:         0x0,
			Common_preempt_count: 0x0,
			Common_pid:           32705,
			Probe_ip:             0xffffffffae6da1f0,
			Dfd:                  0xae6da530,
			Filename:             []byte("file.text\x00"),
			Flags:                0x88241,
			Mode:                 0x1a4,
		},
	},
	{
		name: "gvt_command",
		format: `name: gvt_command
ID: 2034
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:u8 vgpu_id;	offset:8;	size:1;	signed:0;
	field:u8 ring_id;	offset:9;	size:1;	signed:0;
	field:u32 ip_gma;	offset:12;	size:4;	signed:0;
	field:u32 buf_type;	offset:16;	size:4;	signed:0;
	field:u32 buf_addr_type;	offset:20;	size:4;	signed:0;
	field:u32 cmd_len;	offset:24;	size:4;	signed:0;
	field:void* workload;	offset:32;	size:8;	signed:0;
	field:__data_loc u32[] raw_cmd;	offset:40;	size:4;	signed:0;
	field:char cmd_name[40];	offset:44;	size:40;	signed:1;

print fmt: "vgpu%d ring %d: address_type %u, buf_type %u, ip_gma %08x,cmd (name=%s,len=%u,raw cmd=%s), workload=%p
", REC->vgpu_id, REC->ring_id, REC->buf_addr_type, REC->buf_type, REC->ip_gma, REC->cmd_name, REC->cmd_len, __print_array(__get_dynamic_array(raw_cmd), REC->cmd_len, 4), REC->workload
`,
		data: func() []byte {
			b := make([]byte, 84, 84+2*int(unsafe.Sizeof(uint32(0))))
			// Only testing the array parts of this message.
			// All the remainder is left zero.

			// dmd_name:
			for i := 0; i < 40; i++ {
				b[44+i] = byte(i)
			}

			// raw_cmd:
			dataloc := uint32(len(b) | (cap(b)-len(b))<<16)
			dynamic := [...]uint32{0x12345678, 0x9abcdef}
			copy(b[40:], unsafe.Slice((*byte)(unsafe.Pointer(&dataloc)), unsafe.Sizeof(dataloc)))
			b = append(b, unsafe.Slice((*byte)(unsafe.Pointer(&dynamic[0])), unsafe.Sizeof(dynamic))...)

			return b
		}(),
		want: struct {
			Common_type          uint16 `ctyp:"unsigned short" name:"common_type"`
			Common_flags         uint8  `ctyp:"unsigned char" name:"common_flags"`
			Common_preempt_count uint8  `ctyp:"unsigned char" name:"common_preempt_count"`
			Common_pid           int32  `ctyp:"int" name:"common_pid"`
			Vgpu_id              uint8  `ctyp:"u8" name:"vgpu_id"`
			Ring_id              uint8  `ctyp:"u8" name:"ring_id"`
			_pad0                [0]uint8
			Ip_gma               uint32 `ctyp:"u32" name:"ip_gma"`
			Buf_type             uint32 `ctyp:"u32" name:"buf_type"`
			Buf_addr_type        uint32 `ctyp:"u32" name:"buf_addr_type"`
			Cmd_len              uint32 `ctyp:"u32" name:"cmd_len"`
			_pad1                [0]uint8
			Workload             uint64   `ctyp:"void*" name:"workload"`
			Raw_cmd              []uint32 `ctyp:"__data_loc u32[]" name:"raw_cmd"`
			Cmd_name             [40]int8 `ctyp:"char[40]" name:"cmd_name"`
		}{
			Raw_cmd: []uint32{0x12345678, 0x9abcdef},
			Cmd_name: [40]int8{
				0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
				10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
				20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
				30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
			},
		},
	},
}

func TestUnpack(t *testing.T) {
	for _, test := range unpackTests {
		srcTyp, _, _, err := Struct(strings.NewReader(test.format))
		var unaligned UnalignedFieldsError
		if err != nil {
			var ok bool
			if unaligned, ok = err.(UnalignedFieldsError); !ok {
				t.Errorf("unexpected error for aligned %q: %v", test.name, err)
				continue
			}
		}
		dstTyp, err := UnpackedStructFor(srcTyp)
		if err != nil {
			t.Errorf("unexpected error for unaligned %q: %v", test.name, err)
			continue
		}

		src := reflect.NewAt(srcTyp, unsafe.Pointer(&test.data[0]))
		dst := reflect.New(dstTyp)
		err = Unpack(dst, src, unaligned, test.data)
		if err != nil {
			t.Errorf("unexpected error for unpacking %q: %v", test.name, err)
		}

		got := dst.Elem().Interface()
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("unexpected result for %q:\ngot: %#v\nwant:%#v", test.name, got, test.want)
		}
	}
}
