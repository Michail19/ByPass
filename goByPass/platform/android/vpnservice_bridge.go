//go:build android

package android

/*
#include <jni.h>
*/
import "C"
import (
	"unsafe"
)

// VpnServiceBridge предоставляет мост к Android VPNService
type VpnServiceBridge struct {
	env     *C.JNIEnv
	context unsafe.Pointer
}

// NewVpnServiceBridge создает новый мост к VPNService
func NewVpnServiceBridge(env *C.JNIEnv, context unsafe.Pointer) *VpnServiceBridge {
	return &VpnServiceBridge{
		env:     env,
		context: context,
	}
}

// Protect сокета от VPN
func (b *VpnServiceBridge) Protect(socket int) bool {
	// Получаем класс VpnService
	vpnClass := (*C.jclass)(C.FindClass(b.env, C.CString("android/net/VpnService")))
	if vpnClass == nil {
		return false
	}

	// Получаем метод protect
	protectMethod := C.GetMethodID(b.env, vpnClass,
		C.CString("protect"), C.CString("(I)Z"))
	if protectMethod == nil {
		return false
	}

	// Вызываем метод
	result := C.CallBooleanMethod(b.env, b.context, protectMethod, C.jint(socket))
	return result == C.JNI_TRUE
}

// Establish устанавливает VPN туннель
func (b *VpnServiceBridge) Establish(config []byte) int {
	// Получаем метод establish
	establishMethod := C.GetMethodID(b.env,
		C.FindClass(b.env, C.CString("android/net/VpnService")),
		C.CString("establish"), C.CString("()Landroid/os/ParcelFileDescriptor;"))
	if establishMethod == nil {
		return -1
	}

	// Вызываем метод
	pfd := C.CallObjectMethod(b.env, b.context, establishMethod)

	// Получаем дескриптор
	getFdMethod := C.GetMethodID(b.env,
		C.FindClass(b.env, C.CString("android/os/ParcelFileDescriptor")),
		C.CString("getFd"), C.CString("()I"))

	fd := C.CallIntMethod(b.env, pfd, getFdMethod)
	return int(fd)
}
