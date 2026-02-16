//go:build windows

package vfs

import (
	"os"
	"syscall"
	"time"
)

func CompatStat(stat os.FileInfo) (Stat, bool) {
	sysStat, ok := stat.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return Stat{}, false
	}

	s := Stat{
		Ino:     0,
		Blocks:  int64(stat.Size() / 512),
		BlkSize: 4096,
		Mode:    uint32(stat.Mode()),
		Uid:     0,
		Gid:     0,
		Nlink:   1,
		Mtime:   stat.ModTime(),
		Atime:   filetimeToTime(sysStat.LastAccessTime),
		Ctime:   filetimeToTime(sysStat.CreationTime),
		Btime:   filetimeToTime(sysStat.CreationTime),
	}

	if s.Blocks == 0 && stat.Size() > 0 {
		s.Blocks = 1
	}

	return s, true
}

func filetimeToTime(ft syscall.Filetime) time.Time {
	return time.Unix(0, ft.Nanoseconds())
}
