package pki

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gitlab.com/mjwhitta/errors"
	"gitlab.com/mjwhitta/pathname"
)

// database contains all relevant PKI metadata similar to OpenSSL's
// index.db.
type database struct {
	entries      []*certEntry
	mutex        *sync.RWMutex
	root         string
	seen         map[string]struct{}
	serialNumber *big.Int
}

type transaction func() error

// newDatabase will return a pointer to a new database instance.
func newDatabase(root string) (*database, error) {
	var db *database

	// Check that root exists
	if e := ensureExists("dir", root); e != nil {
		return nil, e
	}

	// Create db instance
	db = &database{
		mutex:        &sync.RWMutex{},
		root:         root,
		seen:         map[string]struct{}{},
		serialNumber: big.NewInt(0),
	}

	return db, nil
}

// add will store the cert in the PKI db.
func (db *database) add(cert *x509.Certificate) error {
	return db.commit(
		true,
		func() error {
			var entry *certEntry = newEntry(cert)

			// Do not allow duplicate serial numbers
			if _, ok := db.seen[entry.sn]; ok {
				return errors.Newf(
					"cert with serial number %s already exists",
					entry.sn,
				)
			}

			// Add
			db.entries = append(db.entries, entry)
			db.seen[entry.sn] = struct{}{}

			// Increment db serial number
			db.serialNumber.Add(cert.SerialNumber, big.NewInt(1))

			return nil
		},
	)
}

// commit will write/read lock the db, then it will run the provided
// transaction.
func (db *database) commit(wLock bool, t transaction) error {
	if wLock {
		// Acquire write lock
		db.mutex.Lock()
		defer db.mutex.Unlock()
	} else {
		// Acquire read lock
		db.mutex.RLock()
		defer db.mutex.RUnlock()
	}

	// Sync from files on disk
	if e := db.initialize(); e != nil {
		return e
	}

	// Run transaction
	if e := t(); e != nil {
		return e
	}

	// Sync to files on disk
	if e := db.update(); e != nil {
		return e
	}

	return nil
}

// erase will erase all files related to the PKI db.
func (db *database) erase() error {
	var rms = []string{"index.db", "index.db.attr", "index.db.serial"}

	for _, rm := range rms {
		if e := os.RemoveAll(filepath.Join(db.root, rm)); e != nil {
			return errors.Newf("failed to remove %s: %w", rm, e)
		}
	}

	return nil
}

func (db *database) getCertFor(
	cn string,
	validate bool,
) (*x509.Certificate, error) {
	var e error
	var entry *certEntry

	if validate {
		if entry, e = db.getEntry(cn); e != nil {
			return nil, e
		}

		if entry.file == "unknown" {
			return nil, errors.Newf("cert for %s is missing", cn)
		}
	}

	return getCert(db.root, cn)
}

func (db *database) getEntries() ([]*certEntry, error) {
	var entries []*certEntry
	var t transaction = func() error {
		entries = append(entries, db.entries...)
		return nil
	}

	if e := db.commit(false, t); e != nil {
		return nil, e
	}

	return entries, nil
}

func (db *database) getEntry(cn string) (*certEntry, error) {
	var c *certEntry
	var t transaction = func() error {
		for _, entry := range db.entries {
			if (entry.cn == cn) && !entry.revoked {
				c = entry
				return nil
			}
		}

		return errors.Newf("cert for %s not found", cn)
	}

	if e := db.commit(false, t); e != nil {
		return nil, e
	}

	return c, nil
}

// initialize will create the db if it's missing, otherwise it will
// read it in.
func (db *database) initialize() error {
	if e := db.initializeAttr(); e != nil {
		return e
	}

	if e := db.initializeDB(); e != nil {
		return e
	}

	if e := db.initializeSerial(); e != nil {
		return e
	}

	return nil
}

// initializeAttr will create index.db.attr if it's missing.
func (db *database) initializeAttr() error {
	var f *os.File
	var tmp string = filepath.Join(db.root, "index.db.attr")

	// Create index.db.attr but for now there is no point in reading
	// this file back in.
	if ok, e := pathname.DoesExist(tmp); e != nil {
		return errors.Newf("file %s not accessible: %w", tmp, e)
	} else if !ok {
		if f, e = os.Create(tmp); e != nil {
			return errors.Newf("failed to create %s: %w", tmp, e)
		}
		defer f.Close()

		// Sane permissions
		f.Chmod(rwFilePerms)

		// For now this is hard-coded
		f.WriteString("unique_subject = no\n")
	}

	return nil
}

// initializeDB will create index.db if it's missing, otherwise it
// will read it in.
func (db *database) initializeDB() error {
	var b []byte
	var c *x509.Certificate
	var e error
	var entry *certEntry
	var f *os.File
	var ok bool
	var tmp string = filepath.Join(db.root, "index.db")

	// Reset
	db.entries = []*certEntry{}
	db.seen = map[string]struct{}{}

	// Read or create index.db
	if ok, e = pathname.DoesExist(tmp); e != nil {
		return errors.Newf("file %s not accessible: %w", tmp, e)
	} else if !ok {
		if f, e = os.Create(tmp); e != nil {
			return errors.Newf("failed to create %s: %w", tmp, e)
		}

		// Sane permissions
		f.Chmod(rwFilePerms)
		f.Close()
	} else {
		if b, e = os.ReadFile(tmp); e != nil {
			return errors.Newf("failed to read %s: %w", tmp, e)
		}

		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)

			if line == "" {
				continue
			}

			if entry, e = parseEntry(line); e != nil {
				return errors.Newf("invalid db entry: %w", e)
			}

			if c, e = getCert(db.root, entry.cn); e != nil {
				entry.file = "unknown"
			} else if entry.file == "unknown" {
				tmp = hex.EncodeToString(c.SerialNumber.Bytes())
				if entry.sn == tmp {
					entry.file = filepath.Join(
						"certs",
						entry.cn+".cert.pem",
					)
				}
			}

			db.entries = append(db.entries, entry)
			db.seen[entry.sn] = struct{}{}
		}
	}

	return nil
}

// initializeSerial will create index.db.serial if it's missing,
// otherwise it will read it in.
func (db *database) initializeSerial() error {
	var b []byte
	var e error
	var f *os.File
	var ok bool
	var tmp string = filepath.Join(db.root, "index.db.serial")

	// Read or create index.db.serial
	if ok, e = pathname.DoesExist(tmp); e != nil {
		return errors.Newf("file %s not accessible: %w", tmp, e)
	} else if !ok {
		// Generate serial number
		db.serialNumber, e = rand.Int(rand.Reader, big.NewInt(65535))
		if e != nil {
			e = errors.Newf("failed to generate serial number: %w", e)
			return e
		}

		if f, e = os.Create(tmp); e != nil {
			return errors.Newf("failed to create %s: %w", tmp, e)
		}
		defer f.Close()

		// Sane permissions
		f.Chmod(rwFilePerms)

		// Write as hex
		f.WriteString(hex.EncodeToString(db.serialNumber.Bytes()))
		f.WriteString("\n")
	} else {
		// Read index.db.serial
		if b, e = os.ReadFile(tmp); e != nil {
			return errors.Newf("failed to read %s: %w", tmp, e)
		}

		// Decode hex string
		tmp = strings.TrimSpace(string(b))
		if b, e = hex.DecodeString(tmp); e != nil {
			return errors.Newf("invalid serial number %s: %w", tmp, e)
		}

		// Store serial number
		db.serialNumber.SetBytes(b)
	}

	return nil
}

// isRevoked will return whether or not the cert with the specified
// serial number has been revoked.
func (db *database) isRevoked(sn *big.Int) (bool, error) {
	var revoked bool
	var t transaction = func() error {
		var tmp string = hex.EncodeToString(sn.Bytes())

		for _, entry := range db.entries {
			if entry.sn == tmp {
				revoked = entry.revoked
				return nil
			}
		}

		return nil
	}

	if e := db.commit(false, t); e != nil {
		return false, e
	}

	return revoked, nil
}

// nextSerialNumber will return the next available serial number that
// has not been used.
func (db *database) nextSerialNumber() (*big.Int, error) {
	var sn *big.Int = big.NewInt(0)
	var t transaction = func() error {
		sn.SetBytes(db.serialNumber.Bytes())
		return nil
	}

	if e := db.commit(false, t); e != nil {
		return nil, e
	}

	return sn, nil
}

// revokeCN will update the PKI db to reflect that the oldest cert
// with the specified CN is revoked.
func (db *database) revokeCN(cn string) (*x509.Certificate, error) {
	var c *x509.Certificate
	var e error = db.commit(
		true,
		func() error {
			for _, entry := range db.entries {
				if (entry.cn == cn) && !entry.revoked {
					c, _ = db.getCertFor(cn, false)
					return entry.revoke()
				}
			}

			return errors.Newf("cert for CommonName %s not found", cn)
		},
	)

	return c, e
}

// revokeSN will update the PKI db to reflect that the cert with the
// specified serial number is revoked. It will return the
// corresponding CN.
func (db *database) revokeSN(sn *big.Int) (string, error) {
	var cn string
	var e error = db.commit(
		true,
		func() error {
			var tmp string = hex.EncodeToString(sn.Bytes())

			for _, entry := range db.entries {
				if entry.sn == tmp {
					cn = entry.cn
					return entry.revoke()
				}
			}

			return errors.Newf(
				"cert with serial number %s not found",
				tmp,
			)
		},
	)

	return cn, e
}

// undo will delete the previous entry in the PKI db.
func (db *database) undo() (string, error) {
	var cn string
	var t transaction = func() error {
		var entry *certEntry

		// Return, if no entries to remove
		if len(db.entries) == 0 {
			return nil
		}

		// Get most recent entry
		entry = db.entries[len(db.entries)-1]
		cn = entry.cn

		// Delete
		db.entries = db.entries[:len(db.entries)-1]
		delete(db.seen, entry.sn)

		// Rollback serial number
		db.serialNumber.Sub(db.serialNumber, big.NewInt(1))

		return nil
	}

	if e := db.commit(true, t); e != nil {
		return "", e
	}

	return cn, nil
}

func (db *database) update() error {
	var e error
	var f *os.File
	var tmp string = filepath.Join(db.root, "index.db")

	// Write index.db
	if f, e = os.Create(tmp); e != nil {
		return errors.Newf("failed to create %s: %w", tmp, e)
	}

	// Sane permissions
	f.Chmod(rwFilePerms)

	// Write entries
	for _, entry := range db.entries {
		f.WriteString(entry.String())
		f.WriteString("\n")
	}
	f.Close()

	// Write index.db.serial
	tmp = filepath.Join(db.root, "index.db.serial")
	if f, e = os.Create(tmp); e != nil {
		return errors.Newf("failed to create %s: %w", tmp, e)
	}

	// Sane permissions
	f.Chmod(rwFilePerms)

	// Write as hex
	f.WriteString(hex.EncodeToString(db.serialNumber.Bytes()))
	f.WriteString("\n")
	f.Close()

	return nil
}
