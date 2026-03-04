//go:build linux

package linux

/*
#cgo pkg-config: libnetfilter_queue
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/in.h>
#include <stdlib.h>

// Функции-обертки для вызова из Go
static int nfq_create_queue_bridge(struct nfq_handle *h, uint16_t queue,
                                   nfq_callback *cb, void *data) {
    return (int)(uintptr_t)nfq_create_queue(h, queue, cb, data);
}

static int nfq_set_mode_bridge(struct nfq_q_handle *qh, uint8_t mode, uint32_t len) {
    return nfq_set_mode(qh, mode, len);
}

static int nfq_set_verdict_bridge(struct nfq_q_handle *qh, uint32_t id,
                                 uint32_t verdict, uint32_t mark,
                                 uint32_t datalen, unsigned char *buf) {
    return nfq_set_verdict2(qh, id, verdict, mark, datalen, buf);
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// NFQueueBridge предоставляет Cgo обёртки для NFQUEUE
type NFQueueBridge struct {
	handle *C.struct_nfq_handle
	queue  *C.struct_nfq_q_handle
}

// NewNFQueueBridge создает новый мост к NFQUEUE
func NewNFQueueBridge(queueNum uint16) (*NFQueueBridge, error) {
	handle := C.nfq_open()
	if handle == nil {
		return nil, fmt.Errorf("failed to open nfqueue")
	}

	if C.nfq_unbind_pf(handle, C.AF_INET) < 0 {
		C.nfq_close(handle)
		return nil, fmt.Errorf("failed to unbind AF_INET")
	}

	if C.nfq_bind_pf(handle, C.AF_INET) < 0 {
		C.nfq_close(handle)
		return nil, fmt.Errorf("failed to bind AF_INET")
	}

	// Создаем очередь
	cb := (*[0]byte)(unsafe.Pointer(C.nfqueue_go_callback))
	queue := C.nfq_create_queue_bridge(handle, C.uint16_t(queueNum),
		(C.nfq_callback)(unsafe.Pointer(cb)), nil)
	if queue == nil {
		C.nfq_close(handle)
		return nil, fmt.Errorf("failed to create queue")
	}

	if C.nfq_set_mode_bridge(queue, C.NFQNL_COPY_PACKET, 0xffff) < 0 {
		C.nfq_destroy_queue(queue)
		C.nfq_close(handle)
		return nil, fmt.Errorf("failed to set copy mode")
	}

	return &NFQueueBridge{
		handle: handle,
		queue:  queue,
	}, nil
}

// GetFD возвращает файловый дескриптор
func (b *NFQueueBridge) GetFD() int {
	return int(C.nfq_fd(b.handle))
}

// SetVerdict устанавливает вердикт для пакета
func (b *NFQueueBridge) SetVerdict(id uint32, accept bool, mark uint32, data []byte) error {
	verdict := C.NF_DROP
	if accept {
		verdict = C.NF_ACCEPT
	}

	var dataPtr unsafe.Pointer
	var dataLen C.uint32_t

	if len(data) > 0 {
		dataPtr = unsafe.Pointer(&data[0])
		dataLen = C.uint32_t(len(data))
	}

	ret := C.nfq_set_verdict_bridge(b.queue, C.uint32_t(id), C.uint32_t(verdict),
		C.uint32_t(mark), dataLen, (*C.uchar)(dataPtr))

	if ret < 0 {
		return fmt.Errorf("failed to set verdict: %d", ret)
	}
	return nil
}

// Close закрывает соединение
func (b *NFQueueBridge) Close() {
	if b.queue != nil {
		C.nfq_destroy_queue(b.queue)
	}
	if b.handle != nil {
		C.nfq_close(b.handle)
	}
}
