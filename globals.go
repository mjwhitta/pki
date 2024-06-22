package pki

import "github.com/mjwhitta/errors"

// Errors
var (
	errNoCert error = errors.New("no Certificate provided")
	errNoCN   error = errors.New("no CommonName provided")
)

// Version is the package version.
const Version string = "1.4.9"
