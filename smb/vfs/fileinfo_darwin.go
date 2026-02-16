//go:build darwin

package vfs

import (
	"os"
	"syscall"
	"time"
)

func CompatStat(stat os.FileInfo) (Stat, bool) {
	sysStat, ok := stat.Sys().(*syscall.Stat_t)
	if !ok {
		return Stat{}, false
	}

	s := Stat{
		Ino:     sysStat.Ino,
		Blocks:  sysStat.Blocks,
		BlkSize: int32(sysStat.Blksize),
		Mode:    uint32(sysStat.Mode),
		Uid:     sysStat.Uid,
		Gid:     sysStat.Gid,
		Nlink:   uint32(sysStat.Nlink),
		Atime:   time.Unix(sysStat.Atimespec.Sec, sysStat.Atimespec.Nsec),
		Mtime:   time.Unix(sysStat.Mtimespec.Sec, sysStat.Mtimespec.Nsec),
		Ctime:   time.Unix(sysStat.Ctimespec.Sec, sysStat.Ctimespec.Nsec),
		Btime:   time.Unix(sysStat.Birthtimespec.Sec, sysStat.Birthtimespec.Nsec),
	}

	return s, true
}
