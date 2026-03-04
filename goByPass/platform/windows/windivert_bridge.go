//go:build windows

package windows

/*
#cgo LDFLAGS: -lWinDivert
#include <windows.h>
#include <Windivert.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// WinDivertBridge предоставляет обёртки для WinDivert
type WinDivertBridge struct {
	handle C.HANDLE
}

// NewWinDivertBridge создает новый мост к WinDivert
func NewWinDivertBridge(filter string, priority uint16) (*WinDivertBridge, error) {
	filterPtr := C.CString(filter)
	defer C.free(unsafe.Pointer(filterPtr))

	handle := C.WinDivertOpen(filterPtr, C.WINDIVERT_LAYER_NETWORK, C.int16_t(priority), 0)
	if handle == C.HANDLE(C.INVALID_HANDLE_VALUE) {
		return nil, fmt.Errorf("failed to open WinDivert")
	}

	return &WinDivertBridge{handle: handle}, nil
}

// Recv получает пакет
func (b *WinDivertBridge) Recv() ([]byte, *C.WINDIVERT_ADDRESS, error) {
	packet := make([]byte, 0xFFFF)
	var addr C.WINDIVERT_ADDRESS
	var recvLen C.UINT

	success := C.WinDivertRecv(b.handle, unsafe.Pointer(&packet[0]),
		C.UINT(len(packet)), &recvLen, &addr)

	if success == 0 {
		return nil, nil, fmt.Errorf("failed to receive packet")
	}

	return packet[:recvLen], &addr, nil
}

// Send отправляет пакет
func (b *WinDivertBridge) Send(packet []byte, addr *C.WINDIVERT_ADDRESS) error {
	var sendLen C.UINT

	success := C.WinDivertSend(b.handle, unsafe.Pointer(&packet[0]),
		C.UINT(len(packet)), &sendLen, addr)

	if success == 0 {
		return fmt.Errorf("failed to send packet")
	}

	return nil
}

// Close закрывает соединение
func (b *WinDivertBridge) Close() error {
	if C.WinDivertClose(b.handle) == 0 {
		return fmt.Errorf("failed to close WinDivert")
	}
	return nil
}
