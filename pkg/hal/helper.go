//go:build linux

package hal

import (
	"os"
	"reflect"
	"syscall"
	"unsafe"
)

func mmap(file *os.File, base int64, length int) ([]uint32, []uint8, error) {
	mem8, err := syscall.Mmap(
		int(file.Fd()),
		base,
		length,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED,
	)
	if err != nil {
		return nil, nil, err
	}
	// We'll have to work with 32 bit registers, so let's convert it.
	header := *(*reflect.SliceHeader)(unsafe.Pointer(&mem8))
	header.Len /= (32 / 8)
	header.Cap /= (32 / 8)
	mem32 := *(*[]uint32)(unsafe.Pointer(&header))
	return mem32, mem8, nil
}
