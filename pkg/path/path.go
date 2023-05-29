package path

import (
	"path/filepath"
	"runtime"
)

func GetRootDirectory() string {
	_, currentFile, _, _ := runtime.Caller(0)
	directory := filepath.Join(
		filepath.Dir(currentFile),
		"../..",
	)

	return directory
}
