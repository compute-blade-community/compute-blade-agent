//go:build linux

package hal

import (
	"os"
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

	// Convert []uint8 to []uint32 using unsafe.Slice
	ptr := unsafe.Pointer(&mem8[0])
	mem32 := unsafe.Slice((*uint32)(ptr), len(mem8)/4)

	return mem32, mem8, nil
}
