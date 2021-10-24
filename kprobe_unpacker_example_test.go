// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package kprobe_test

import (
	"fmt"
	"io"
	"log"
	"reflect"
	"strings"
	"unsafe"

	"github.com/kortschak/kprobe"
)

type Unpacker map[string]func(data []byte) (interface{}, error)

func (u Unpacker) Register(format io.Reader) error {
	srcTyp, name, _, err := kprobe.Struct(format)
	if err == nil {
		// Fast path with layout consistent between kprobe
		// event and Go struct.
		u[name] = func(data []byte) (interface{}, error) {
			return reflect.NewAt(srcTyp, unsafe.Pointer(&data[0])), nil
		}
		return nil
	}

	var unaligned kprobe.UnalignedFieldsError
	if err != nil {
		var ok bool
		if unaligned, ok = err.(kprobe.UnalignedFieldsError); !ok {
			return err
		}
	}
	dstTyp, err := kprobe.UnpackedStructFor(srcTyp)
	if err != nil {
		return err
	}
	// Slow path with either unaligned fields or dynamic arrays.
	u[name] = func(data []byte) (interface{}, error) {
		src := reflect.NewAt(srcTyp, unsafe.Pointer(&data[0]))
		dst := reflect.New(dstTyp)
		err = kprobe.Unpack(dst, src, unaligned, data)
		return dst, err
	}
	return nil
}

func (u Unpacker) Unpack(stream string, data []byte) (interface{}, error) {
	f, ok := u[stream]
	if !ok {
		return nil, fmt.Errorf("no unpacker for %s", stream)
	}
	return f(data)
}

var formats = []string{
	`name: do_sys_open
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
	`name: ip_local_out_call
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
	`name: vfs_read
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
}

func Example_unpacker() {
	// Perform one-time format registration.
	u := make(Unpacker)
	for _, f := range formats {
		err := u.Register(strings.NewReader(f))
		if err != nil {
			log.Fatal(err)
		}
	}

	// Process stream of events.
	events := []struct {
		stream string
		data   []byte
	}{
		{
			stream: "do_sys_open",
			data: []byte{
				0xb2, 0x1b, 0x00, 0x00, 0xc1, 0x7f, 0x00, 0x00,
				0xf0, 0xa1, 0x6d, 0xae, 0xff, 0xff, 0xff, 0xff,
				0x30, 0xa5, 0x6d, 0xae, 0x20, 0x00, 0x0a, 0x00,
				0x41, 0x82, 0x08, 0x00, 0xa4, 0x01, 0x00, 0x00,
				0x66, 0x69, 0x6c, 0x65, 0x2e, 0x74, 0x65, 0x78,
				0x74, 0x00, 0x00, 0x00,
			},
		},
		{
			stream: "ip_local_out_call",
			data: []byte{
				0x7d, 0x0f, 0x00, 0x00, 0xc7, 0x29, 0x00, 0x00,
				0x0f, 0x2b, 0xdb, 0xef, 0x00, 0x00, 0x00, 0x00,
				0x40, 0xe0, 0x73, 0x97, 0x7d, 0x9e, 0x00, 0x00,
				0x3c, 0x00, 0x00, 0x00, 0x02, 0x00, 0x7f, 0x00,
				0x00, 0x01, 0xde, 0xad, 0x7f, 0x00, 0x00, 0x01,
				0xbe, 0xef, 0x00, 0x00,
			},
		},
		{
			stream: "vfs_read",
			data: []byte{
				0x4e, 0xd1, 0x00, 0x00, 0x73, 0x1e, 0x00, 0x00,
				0x0f, 0xeb, 0xd4, 0x3f, 0x00, 0x00, 0x00, 0x00,
				0xb0, 0x1d, 0xfa, 0xce, 0x11, 0xe5, 0x00, 0x00,
				0x52, 0x12, 0x1b, 0x81, 0xff, 0xff, 0xff, 0xff,
			},
		},
	}

	for _, e := range events {
		v, err := u.Unpack(e.stream, e.data)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%+v\n", v)
	}

	// Output:
	// &{Common_type:7090 Common_flags:0 Common_preempt_count:0 Common_pid:32705 Probe_ip:18446744072341004784 Dfd:2926421296 Filename:[102 105 108 101 46 116 101 120 116 0] Flags:557633 Mode:420}
	// &{Common_type:3965 Common_flags:0 Common_preempt_count:0 Common_pid:10695 Probe_ip:4024118031 Sock:174262249054272 Size:60 Af:2 Laddr:16777343 Lport:44510 Raddr:16777343 Rport:61374}
	// &{Common_type:53582 Common_flags:0 Common_preempt_count:0 Common_pid:7795 Probe_ip:1070918415 Arg1:251864649702832 Arg2:[82 18 27 129 255 255 255 255]}
}
