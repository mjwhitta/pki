package pki

import (
	"crypto/x509"
	"encoding/hex"
	"path/filepath"
	"strings"
	"time"

	"github.com/mjwhitta/errors"
)

// certEntry is a struct containing relavant data for an entry in the
// PKI's db.
type certEntry struct {
	cn      string
	expired bool
	expires string
	file    string
	name    string
	revoked bool
	revokes string
	sn      string
	status  string
}

func newEntry(cert *x509.Certificate) *certEntry {
	var cn string = cert.Subject.CommonName
	var entry *certEntry = &certEntry{
		cn:      cn,
		expires: cert.NotAfter.UTC().Format("060102150405") + "Z",
		file:    "unknown", // Default
		revokes: "",
		sn:      hex.EncodeToString(cert.SerialNumber.Bytes()),
		status:  "V",
	}
	var tmp []string = strings.Split(cert.Subject.String(), ",")

	// Set filepath based on CN
	entry.file = filepath.Join("certs", cn+".cert.pem")

	// Build distinguished name to match OpenSSL format
	for i := 0; i < len(tmp)/2; i++ {
		j := len(tmp) - i - 1
		tmp[i], tmp[j] = tmp[j], tmp[i]
	}
	entry.name = "/" + strings.Join(tmp, "/")

	// Check if expired
	if time.Now().After(cert.NotAfter) {
		entry.expired = true
		entry.status = "E"
	}

	return entry
}

func parseEntry(str string) (*certEntry, error) {
	var entry *certEntry
	var tmp []string = strings.Split(str, "\t")

	if len(tmp) != 6 {
		return nil, errors.Newf("failed to parse cert entry: %s", str)
	}

	entry = &certEntry{
		expires: tmp[1],
		file:    tmp[4],
		name:    tmp[5],
		revokes: tmp[2],
		sn:      tmp[3],
		status:  tmp[0],
	}

	// Ensure file has a sane default value
	if entry.file == "" {
		entry.file = "unknown"
	}

	// Validate status
	switch entry.status {
	case "E":
		entry.expired = true
	case "R":
		entry.revoked = true
	case "V":
	default:
		return nil, errors.Newf("invalid entry %s", str)
	}

	// Parse distinguished name to get CN
	for _, s := range strings.Split(entry.name, "/") {
		if strings.HasPrefix(s, "CN=") {
			entry.cn = strings.TrimSpace(s[3:])
			break
		}
	}

	return entry, nil
}

// revoke will update the entry to reflect it was revoked and at what
// time.
func (c *certEntry) revoke() error {
	if c.revoked {
		return errors.Newf("cert for %s already revoked", c.cn)
	}

	c.file = "unknown"
	c.revoked = true
	c.revokes = time.Now().UTC().Format("060102150405") + "Z"
	c.status = "R"

	return nil
}

// String will return the string representation of a certEntry.
func (c *certEntry) String() string {
	var out = []string{
		c.status,
		c.expires,
		c.revokes,
		c.sn,
		c.file,
		c.name,
	}

	return strings.Join(out, "\t")
}
