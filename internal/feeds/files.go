package feeds

import (
	"os"
	"path/filepath"
)

// WriteFile writes data to path through a temporary file and a rename, creating the parent
// directory when needed.
func WriteFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".part"
	//nolint:gosec // G703: path is built from the configured data directory and a fixed name
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
