package api

import "C"
import (
	"encoding/json"
	"mydpi/internal/core"
)

// Экспортируемые функции для gomobile

//export StartBypass
func StartBypass(platform *C.char, configJSON *C.char) *C.char {
	platformStr := C.GoString(platform)
	configStr := C.GoString(configJSON)

	var config map[string]interface{}
	if err := json.Unmarshal([]byte(configStr), &config); err != nil {
		return C.CString("error: " + err.Error())
	}

	result, err := core.Start(platformStr, config)
	if err != nil {
		return C.CString("error: " + err.Error())
	}

	return C.CString(result)
}

//export StopBypass
func StopBypass() {
	core.Stop()
}

//export GetStatus
func GetStatus() *C.char {
	status, _ := json.Marshal(core.GetStatus())
	return C.CString(string(status))
}
