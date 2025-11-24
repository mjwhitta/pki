package pki

import "github.com/mjwhitta/errors"

// Version is the package version.
const Version string = "1.5.1"

// Errors
var (
	errNoCert error = errors.New("no Certificate provided")
	errNoCN   error = errors.New("no CommonName provided")
)
