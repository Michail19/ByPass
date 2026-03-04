//go:build windows
// +build windows

package capture

// newPlatformCapturer создает захватчик для Windows
func newPlatformCapturer(cfg Config) (Capturer, error) {
	return NewWinDivert(cfg)
}
