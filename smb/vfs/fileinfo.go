package vfs

import "time"

type Stat struct {
	Ino     uint64
	Blocks  int64
	BlkSize int32
	Mode    uint32
	Uid     uint32
	Gid     uint32
	Nlink   uint32
	Mtime   time.Time
	Atime   time.Time
	Ctime   time.Time
	Btime   time.Time
}
