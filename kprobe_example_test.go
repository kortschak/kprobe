// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package kprobe_test

import (
	"fmt"
	"log"
	"reflect"
	"strings"
	"unsafe"

	"github.com/kortschak/kprobe"
)

func ExampleStruct() {
	format := `name: ip_local_out_call
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
`

	srcTyp, name, id, err := kprobe.Struct(strings.NewReader(format), true)
	var unaligned kprobe.UnalignedFieldsError
	if err != nil {
		var ok bool
		if unaligned, ok = err.(kprobe.UnalignedFieldsError); !ok {
			log.Fatal(err)
		}
		fmt.Printf("warning: %v\n", err)
	}
	fmt.Println(name, id)

	data := []byte{
		0x7d, 0x0f, 0x00, 0x00, 0xc7, 0x29, 0x00, 0x00,
		0x0f, 0x2b, 0xdb, 0xef, 0x00, 0x00, 0x00, 0x00,
		0x40, 0xe0, 0x73, 0x97, 0x7d, 0x9e, 0x00, 0x00,
		0x3c, 0x00, 0x00, 0x00, 0x02, 0x00, 0x7f, 0x00,
		0x00, 0x01, 0xde, 0xad, 0x7f, 0x00, 0x00, 0x01,
		0xbe, 0xef, 0x00, 0x00,
	}

	src := reflect.NewAt(srcTyp, unsafe.Pointer(&data[0]))
	fmt.Printf("src: %+v\n", src)

	dstTyp, _, _, err := kprobe.Struct(strings.NewReader(format), false)
	if err != nil {
		log.Fatal(err)
	}
	dst := reflect.New(dstTyp)
	err = kprobe.Copy(dst, src, unaligned)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("dst: %+v\n", dst)

	// Output:
	// warning: unaligned fields in struct: [8]
	// ip_local_out_call 3226
	// src: &{Common_type:3965 Common_flags:0 Common_preempt_count:0 Common_pid:10695 Probe_ip:4024118031 Sock:174262249054272 Size:60 Af:2 Laddr:[127 0 0 1] Lport:44510 Raddr:16777343 Rport:61374}
	// dst: &{Common_type:3965 Common_flags:0 Common_preempt_count:0 Common_pid:10695 Probe_ip:4024118031 Sock:174262249054272 Size:60 Af:2 Laddr:16777343 Lport:44510 Raddr:16777343 Rport:61374}
}
