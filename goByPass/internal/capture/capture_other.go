//go:build !linux && !windows
// +build !linux,!windows

package capture

import "fmt"

// newPlatformCapturer для неподдерживаемых платформ
func newPlatformCapturer(cfg Config) (Capturer, error) {
	return nil, fmt.Errorf("capture not supported on this platform")
}
