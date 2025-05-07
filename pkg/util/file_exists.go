package util

import "os"

// FileExists checks if a file exists at the given path and returns true if it does, false otherwise.
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
