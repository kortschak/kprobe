# kprobe

The kprobe package allows construction of dynamic struct based on kprobe event format descriptions.

```
name: p_vfs_read_0
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
```

gives

```
struct {
	Common_type          uint16   `ctyp:"unsigned short" name:"common_type"`
	Common_flags         uint8    `ctyp:"unsigned char" name:"common_flags"`
	Common_preempt_count uint8    `ctyp:"unsigned char" name:"common_preempt_count"`
	Common_pid           int32    `ctyp:"int" name:"common_pid"`
	Probe_ip             uint64   `ctyp:"unsigned long" name:"__probe_ip"`
	Arg1                 uint64   `ctyp:"u64" name:"arg1"`
	Arg2                 [8]uint8 `ctyp:"u8[8]" name:"arg2"`
}
```

kprobe will ensure that fields are correctly padded so that the offsets in the format are reflected in the constructed struct.

```
name: myprobe
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
```

gives 

```
struct {
	Common_type          uint16   `ctyp:"unsigned short" name:"common_type"`
	Common_flags         uint8    `ctyp:"unsigned char" name:"common_flags"`
	Common_preempt_count uint8    `ctyp:"unsigned char" name:"common_preempt_count"`
	Common_pid           int32    `ctyp:"int" name:"common_pid"`
	_                    [4]uint8 `pad:"0" bytes:"[8:12]"`
	Probe_ip             uint32   `ctyp:"unsigned long" name:"__probe_ip"`
	Probe_nargs          int32    `ctyp:"int" name:"__probe_nargs"`
	Dfd                  uint32   `ctyp:"unsigned long" name:"dfd"`
	Filename             uint32   `ctyp:"unsigned long" name:"filename"`
	Flags                uint32   `ctyp:"unsigned long" name:"flags"`
	Mode                 uint32   `ctyp:"unsigned long" name:"mode"`
}
```
