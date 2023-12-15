package pki

import (
	"os"

	"github.com/mjwhitta/errors"
)

// Errors
var errNoCert error = errors.New("no Certificate provided")
var errNoCN error = errors.New("no CommonName provided")

// Permissions for directories and files
var rwDirPerms os.FileMode = (os.ModeDir | os.ModePerm) & 0o700
var roFilePerms os.FileMode = os.ModePerm & 0o400
var rwFilePerms os.FileMode = os.ModePerm & 0o600

// Version is the package version.
const Version = "1.4.4"
