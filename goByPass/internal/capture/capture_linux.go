//go:build linux
// +build linux

package capture

// newPlatformCapturer создает захватчик для Linux
func newPlatformCapturer(cfg Config) (Capturer, error) {
	return NewNFQueue(cfg)
}
