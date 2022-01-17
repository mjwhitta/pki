package pki

// CertType is an enumeration of supported certificate types.
type CertType int

// Certificate types
const (
	CACert CertType = iota
	ClientCert
	ServerCert
)
