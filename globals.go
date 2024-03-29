package pki

import (
	"os"

	"github.com/mjwhitta/errors"
)

// Errors
var (
	errNoCert error = errors.New("no Certificate provided")
	errNoCN   error = errors.New("no CommonName provided")
)

// Permissions for directories and files
var (
	rwDirPerms  os.FileMode = (os.ModeDir | os.ModePerm) & 0o700
	roFilePerms os.FileMode = os.ModePerm & 0o400
	rwFilePerms os.FileMode = os.ModePerm & 0o600
)

// Version is the package version.
const Version string = "1.4.8"
