package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/sambam/sambam/smb/vfs"
)

type OpenFile struct {
	path   string
	isDir  bool
	f      *os.File
	h      vfs.VfsHandle
	dirPos int
}

type PassthroughFS struct {
	rootPath  string
	readOnly  bool
	openFiles sync.Map
}

func NewPassthroughFS(rootPath string, readOnly bool) *PassthroughFS {
	return &PassthroughFS{
		rootPath:  rootPath,
		readOnly:  readOnly,
		openFiles: sync.Map{},
	}
}

func (fs *PassthroughFS) GetAttr(handle vfs.VfsHandle) (*vfs.Attributes, error) {
	p := fs.rootPath
	if handle != 0 {
		v, ok := fs.openFiles.Load(handle)
		if !ok {
			return nil, fmt.Errorf("bad handle")
		}
		open := v.(*OpenFile)
		p = open.path
	}

	info, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}

	return fileInfoToAttr(info)
}

func (fs *PassthroughFS) SetAttr(handle vfs.VfsHandle, a *vfs.Attributes) (*vfs.Attributes, error) {
	if fs.readOnly {
		return nil, fmt.Errorf("read-only share")
	}

	if handle == 0 {
		return nil, fmt.Errorf("bad handle")
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		return nil, fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)

	oldAttrs, err := fs.GetAttr(handle)
	if err != nil {
		return nil, fmt.Errorf("failed to read attributes")
	}

	atime, atimeSet := a.GetAccessTime()
	if !atimeSet {
		atime, _ = oldAttrs.GetAccessTime()
	}
	mtime, mtimeSet := a.GetLastDataModificationTime()
	if !mtimeSet {
		mtime, _ = oldAttrs.GetLastDataModificationTime()
	}

	if atimeSet || mtimeSet {
		os.Chtimes(open.path, atime, mtime)
	}

	if mode, mSet := a.GetUnixMode(); mSet {
		os.Chmod(open.path, os.FileMode(mode))
	}

	return nil, nil
}

func (fs *PassthroughFS) StatFS(handle vfs.VfsHandle) (*vfs.FSAttributes, error) {
	a := vfs.FSAttributes{}
	// Return some reasonable defaults
	a.SetAvailableBlocks(1000000)
	a.SetBlockSize(4096)
	a.SetBlocks(10000000)
	a.SetFiles(1000000)
	a.SetFreeBlocks(1000000)
	a.SetFreeFiles(1000000)
	a.SetIOSize(4096)
	return &a, nil
}

func (fs *PassthroughFS) FSync(handle vfs.VfsHandle) error {
	if handle == 0 {
		return fmt.Errorf("bad handle")
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		return fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)
	return open.f.Sync()
}

func (fs *PassthroughFS) Flush(handle vfs.VfsHandle) error {
	return nil
}

func randHandle() uint64 {
	var b [8]byte
	rand.Read(b[:])
	return binary.LittleEndian.Uint64(b[:])
}

func (fs *PassthroughFS) Open(p string, flags int, mode int) (vfs.VfsHandle, error) {
	fullPath := path.Join(fs.rootPath, p)

	// If read-only, force read-only flags
	if fs.readOnly {
		flags = os.O_RDONLY
	}

	f, err := os.OpenFile(fullPath, flags, os.FileMode(mode))
	if err != nil {
		return 0, err
	}

	h := vfs.VfsHandle(randHandle())
	fs.openFiles.Store(h, &OpenFile{f: f, h: h, path: fullPath})

	return h, nil
}

func (fs *PassthroughFS) Close(handle vfs.VfsHandle) error {
	v, ok := fs.openFiles.Load(handle)
	if !ok {
		return fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)

	open.f.Close()
	fs.openFiles.Delete(handle)

	return nil
}

func (fs *PassthroughFS) Lookup(handle vfs.VfsHandle, name string) (*vfs.Attributes, error) {
	p := fs.rootPath
	if handle != 0 {
		v, ok := fs.openFiles.Load(handle)
		if !ok {
			return nil, fmt.Errorf("bad handle")
		}
		open := v.(*OpenFile)
		p = open.path
	}

	info, err := os.Lstat(path.Join(p, name))
	if err != nil {
		return nil, err
	}

	return fileInfoToAttr(info)
}

func (fs *PassthroughFS) Mkdir(p string, mode int) (*vfs.Attributes, error) {
	if fs.readOnly {
		return nil, fmt.Errorf("read-only share")
	}

	fullPath := path.Join(fs.rootPath, p)
	if err := os.Mkdir(fullPath, os.FileMode(mode)); err != nil {
		return nil, err
	}

	info, err := os.Stat(fullPath)
	if err != nil {
		return nil, err
	}

	return fileInfoToAttr(info)
}

func (fs *PassthroughFS) Read(handle vfs.VfsHandle, buf []byte, offset uint64, flags int) (int, error) {
	if handle == 0 {
		return 0, io.EOF
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		// Handle was closed - this can happen with parallel reads
		return 0, io.EOF
	}
	open := v.(*OpenFile)

	n, err := open.f.ReadAt(buf, int64(offset))
	// If file was closed during read (race with Close), return EOF
	if err != nil && (os.IsNotExist(err) || isClosedError(err)) {
		return n, io.EOF
	}
	return n, err
}

// isClosedError checks if the error is due to a closed file descriptor
func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "bad file descriptor") ||
		strings.Contains(errStr, "file already closed")
}

func (fs *PassthroughFS) Write(handle vfs.VfsHandle, buf []byte, offset uint64, flags int) (int, error) {
	if fs.readOnly {
		return 0, fmt.Errorf("read-only share")
	}

	if handle == 0 {
		return 0, fmt.Errorf("bad handle")
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		return 0, fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)

	return open.f.WriteAt(buf, int64(offset))
}

func (fs *PassthroughFS) OpenDir(p string) (vfs.VfsHandle, error) {
	fullPath := path.Join(fs.rootPath, p)
	f, err := os.OpenFile(fullPath, os.O_RDONLY, 0)
	if err != nil {
		return 0, err
	}

	h := vfs.VfsHandle(randHandle())
	fs.openFiles.Store(h, &OpenFile{f: f, h: h, path: fullPath, isDir: true})

	return h, nil
}

func (fs *PassthroughFS) ReadDir(handle vfs.VfsHandle, pos int, maxEntries int) ([]vfs.DirInfo, error) {
	if handle == 0 {
		return nil, nil
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		return nil, fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)

	var results []vfs.DirInfo
	if pos != 0 {
		open.f.Seek(0, 0)
		open.dirPos = 0
	}

	if open.dirPos == 0 {
		attrs, err := fs.GetAttr(open.h)
		if err != nil {
			return nil, err
		}

		results = append(results,
			vfs.DirInfo{Name: ".", Attributes: *attrs},
			vfs.DirInfo{Name: "..", Attributes: *attrs})
	}

	entries, err := open.f.ReadDir(maxEntries)
	if err != nil && (err != io.EOF || open.dirPos != 0) {
		return nil, err
	}

	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		attrs, err := fileInfoToAttr(info)
		if err != nil {
			continue
		}
		results = append(results, vfs.DirInfo{Name: entry.Name(), Attributes: *attrs})
	}
	open.dirPos = 1

	return results, nil
}

func (fs *PassthroughFS) Readlink(handle vfs.VfsHandle) (string, error) {
	if handle == 0 {
		return "", fmt.Errorf("bad handle")
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		return "", fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)
	return os.Readlink(open.path)
}

func (fs *PassthroughFS) Unlink(handle vfs.VfsHandle) error {
	if fs.readOnly {
		return fmt.Errorf("read-only share")
	}

	if handle == 0 {
		return fmt.Errorf("bad handle")
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		return fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)

	return os.Remove(open.path)
}

func (fs *PassthroughFS) Truncate(handle vfs.VfsHandle, length uint64) error {
	if fs.readOnly {
		return fmt.Errorf("read-only share")
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		return fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)

	return os.Truncate(open.path, int64(length))
}

func (fs *PassthroughFS) Rename(from vfs.VfsHandle, to string, flags int) error {
	if fs.readOnly {
		return fmt.Errorf("read-only share")
	}

	if from == 0 {
		return fmt.Errorf("bad handle")
	}

	v, ok := fs.openFiles.Load(from)
	if !ok {
		return fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)

	if flags == 0 {
		if _, err := os.Stat(to); err == nil {
			return fmt.Errorf("already exists")
		}
	}

	return os.Rename(open.path, path.Join(fs.rootPath, to))
}

func (fs *PassthroughFS) Symlink(targetHandle vfs.VfsHandle, source string, flag int) (*vfs.Attributes, error) {
	return nil, fmt.Errorf("symlinks not supported")
}

func (fs *PassthroughFS) Link(vfs.VfsNode, vfs.VfsNode, string) (*vfs.Attributes, error) {
	return nil, fmt.Errorf("hard links not supported")
}

func (fs *PassthroughFS) Listxattr(handle vfs.VfsHandle) ([]string, error) {
	return nil, nil
}

func (fs *PassthroughFS) Getxattr(handle vfs.VfsHandle, key string, val []byte) (int, error) {
	return 0, fmt.Errorf("xattrs not supported")
}

func (fs *PassthroughFS) Setxattr(handle vfs.VfsHandle, key string, val []byte) error {
	return fmt.Errorf("xattrs not supported")
}

func (fs *PassthroughFS) Removexattr(handle vfs.VfsHandle, key string) error {
	return fmt.Errorf("xattrs not supported")
}

func fileInfoToAttr(stat os.FileInfo) (*vfs.Attributes, error) {
	sysStat, ok := vfs.CompatStat(stat)
	if !ok {
		return nil, fmt.Errorf("failed to convert stat")
	}

	a := vfs.Attributes{}
	a.SetInodeNumber(sysStat.Ino)
	a.SetSizeBytes(uint64(stat.Size()))
	a.SetDiskSizeBytes(uint64(sysStat.Blocks * 512))
	a.SetUnixMode(uint32(stat.Mode()))
	a.SetPermissions(vfs.NewPermissionsFromMode(uint32(stat.Mode().Perm())))
	a.SetAccessTime(sysStat.Atime)
	a.SetLastDataModificationTime(stat.ModTime())
	a.SetBirthTime(sysStat.Btime)
	a.SetLastStatusChangeTime(sysStat.Ctime)

	if stat.IsDir() {
		a.SetFileType(vfs.FileTypeDirectory)
	} else if stat.Mode()&os.ModeSymlink != 0 {
		a.SetFileType(vfs.FileTypeSymlink)
	} else {
		a.SetFileType(vfs.FileTypeRegularFile)
	}

	return &a, nil
}
