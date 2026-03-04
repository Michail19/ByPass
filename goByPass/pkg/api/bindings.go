//go:build android || ios
// +build android ios

package api

/*
#include <stdlib.h>
*/
import "C"
import (
	"ByPass/internal/core"
	"encoding/json"
	"unsafe"
)

// Экспортируемые функции для gomobile

//export StartBypass
func StartBypass(configJSON *C.char) *C.char {
	configStr := C.GoString(configJSON)

	var config MobileConfig
	if err := json.Unmarshal([]byte(configStr), &config); err != nil {
		return C.CString("error: " + err.Error())
	}

	// Запускаем ядро DPI-обхода
	if err := core.StartMobile(config); err != nil {
		return C.CString("error: " + err.Error())
	}

	return C.CString("success")
}

//export StopBypass
func StopBypass() {
	core.StopMobile()
}

//export GetStats
func GetStats() *C.char {
	stats := core.GetMobileStats()
	data, _ := json.Marshal(stats)
	return C.CString(string(data))
}

//export SetProxyPort
func SetProxyPort(port C.int) {
	core.SetProxyPort(int(port))
}

//export AddBypassDomain
func AddBypassDomain(domain *C.char) {
	core.AddBypassDomain(C.GoString(domain))
}

//export RemoveBypassDomain
func RemoveBypassDomain(domain *C.char) {
	core.RemoveBypassDomain(C.GoString(domain))
}

//export GetVersion
func GetVersion() *C.char {
	return C.CString("1.0.0")
}

// FreeString освобождает память, выделенную под C-строку
//
//export FreeString
func FreeString(str *C.char) {
	C.free(unsafe.Pointer(str))
}
