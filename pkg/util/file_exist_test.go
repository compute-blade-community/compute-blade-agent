package util_test

import (
	"os"
	"testing"

	"github.com/compute-blade-community/compute-blade-agent/pkg/util"
	"github.com/stretchr/testify/assert"
)

func TestFileExists(t *testing.T) {
	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "fileexists-test")
	assert.NoError(t, err)

	// It should exist
	assert.True(t, util.FileExists(tmpFile.Name()), "Expected file to exist")

	// Close and remove the file
	assert.NoError(t, tmpFile.Close())
	assert.NoError(t, os.Remove(tmpFile.Name()))

	// It should not exist anymore
	assert.False(t, util.FileExists(tmpFile.Name()), "Expected file not to exist")
}
