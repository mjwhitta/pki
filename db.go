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

	"github.com/mjwhitta/errors"
	"github.com/mjwhitta/pathname"
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
	var files []string = []string{
		"index.db",
		"index.db.attr",
		"index.db.serial",
	}

	for _, fn := range files {
		if e := os.RemoveAll(filepath.Join(db.root, fn)); e != nil {
			return errors.Newf("failed to remove %s: %w", fn, e)
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
	var fn string = filepath.Join(db.root, "index.db.attr")

	// Create index.db.attr but for now there is no point in reading
	// this file back in.
	if ok, e := pathname.DoesExist(fn); e != nil {
		return errors.Newf("file %s not accessible: %w", fn, e)
	} else if !ok {
		e = os.WriteFile(
			fn,
			// For now this is hard-coded
			[]byte("unique_subject = no\n"),
			0o600, //nolint:mnd // u=rw,go=-
		)
		if e != nil {
			return errors.Newf("failed to create %s: %w", fn, e)
		}
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
	var fn string = filepath.Join(db.root, "index.db")
	var ok bool

	// Reset
	db.entries = []*certEntry{}
	db.seen = map[string]struct{}{}

	// Read or create index.db
	if ok, e = pathname.DoesExist(fn); e != nil {
		return errors.Newf("file %s not accessible: %w", fn, e)
	} else if !ok {
		//nolint:mnd // u=rw,go=-
		if e = os.WriteFile(fn, nil, 0o600); e != nil {
			return errors.Newf("failed to create %s: %w", fn, e)
		}
	} else {
		fn = filepath.Clean(fn)
		if b, e = os.ReadFile(fn); e != nil {
			return errors.Newf("failed to read %s: %w", fn, e)
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
				fn = hex.EncodeToString(c.SerialNumber.Bytes())
				if entry.sn == fn {
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
	var fn string = filepath.Join(db.root, "index.db.serial")
	var ok bool
	var serial string

	fn = filepath.Clean(fn)

	// Read or create index.db.serial
	if ok, e = pathname.DoesExist(fn); e != nil {
		return errors.Newf("file %s not accessible: %w", fn, e)
	} else if !ok {
		// Generate random serial number
		b = make([]byte, 16) //nolint:mnd // 128 bits
		if _, e = rand.Read(b); e != nil {
			e = errors.Newf("failed to generate serial number: %w", e)
			return e
		}

		// Set serial number
		db.serialNumber = big.NewInt(0).SetBytes(b)

		// Write as hex
		b = []byte(hex.EncodeToString(db.serialNumber.Bytes()) + "\n")

		//nolint:mnd // u=rw,go=-
		if e = os.WriteFile(fn, b, 0o600); e != nil {
			return errors.Newf("failed to create %s: %w", fn, e)
		}
	} else {
		// Read index.db.serial
		if b, e = os.ReadFile(fn); e != nil {
			return errors.Newf("failed to read %s: %w", fn, e)
		}

		// Decode hex string
		serial = strings.TrimSpace(string(b))
		if b, e = hex.DecodeString(serial); e != nil {
			e = errors.Newf("invalid serial number %s: %w", serial, e)
			return e
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
		var serial string = hex.EncodeToString(sn.Bytes())

		for _, entry := range db.entries {
			if entry.sn == serial {
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

	if e != nil {
		return nil, e
	}

	return c, nil
}

// revokeSN will update the PKI db to reflect that the cert with the
// specified serial number is revoked. It will return the
// corresponding CN.
func (db *database) revokeSN(sn *big.Int) (string, error) {
	var cn string
	var e error = db.commit(
		true,
		func() error {
			var serial string = hex.EncodeToString(sn.Bytes())

			for _, entry := range db.entries {
				if entry.sn == serial {
					cn = entry.cn
					return entry.revoke()
				}
			}

			return errors.Newf(
				"cert with serial number %s not found",
				serial,
			)
		},
	)

	if e != nil {
		return "", e
	}

	return cn, nil
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

func (db *database) update() (e error) {
	var f *os.File
	var files []string = []string{
		filepath.Join(db.root, "index.db"),
		filepath.Join(db.root, "index.db.serial"),
	}

	// Write index.db
	if f, e = os.Create(files[0]); e != nil {
		return errors.Newf("failed to create %s: %w", files[0], e)
	}
	defer func(f *os.File) {
		if e == nil {
			e = f.Close()
		}
	}(f)

	// Sane permissions
	if e = f.Chmod(0o600); e != nil { //nolint:mnd // u=rw,go=-
		return errors.Newf("failed to modify permissions: %w", e)
	}

	// Write entries
	for _, entry := range db.entries {
		_, _ = f.WriteString(entry.String() + "\n")
	}

	// Write index.db.serial
	if f, e = os.Create(filepath.Clean(files[1])); e != nil {
		return errors.Newf("failed to create %s: %w", files[1], e)
	}
	defer func(f *os.File) {
		if e == nil {
			e = f.Close()
		}
	}(f)

	// Sane permissions
	if e = f.Chmod(0o600); e != nil { //nolint:mnd // u=rw,go=-
		return errors.Newf("failed to modify permissions: %w", e)
	}

	// Write as hex
	_, _ = f.WriteString(
		hex.EncodeToString(db.serialNumber.Bytes()) + "\n",
	)

	return nil
}
