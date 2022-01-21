package pki

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"io/ioutil"
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

// newDatabase will return a pointer to a new database instance.
func newDatabase(root string) (*database, error) {
	var db *database
	var e error
	var sn *big.Int

	// Check that root exists
	if e = ensureExists("dir", root); e != nil {
		return nil, e
	}

	// Generate serial number
	if sn, e = rand.Int(rand.Reader, big.NewInt(65535)); e != nil {
		e = errors.Newf("failed to generate serial number: %w", e)
		return nil, e
	}

	// Create db instance
	db = &database{
		mutex:        &sync.RWMutex{},
		root:         root,
		seen:         map[string]struct{}{},
		serialNumber: sn,
	}

	// Initialize the db
	if e = db.initialize(); e != nil {
		return nil, e
	}

	return db, nil
}

// add will store the cert in the PKI db.
func (db *database) add(cert *x509.Certificate) error {
	var entry *certEntry = newEntry(cert)

	// Lock while adding
	db.mutex.Lock()
	defer db.mutex.Unlock()

	// Do not allow duplicate serial numbers
	if _, ok := db.seen[entry.sn]; ok {
		return errors.Newf(
			"certificate with serial number %s already exists",
			entry.sn,
		)
	}

	// Add
	db.entries = append(db.entries, entry)
	db.seen[entry.sn] = struct{}{}

	// Increment db serial number
	db.serialNumber.Add(cert.SerialNumber, big.NewInt(1))

	// Update files on disk
	return db.update()
}

// erase will erase all files related to the PKI db.
func (db *database) erase() error {
	var e error
	var rms = []string{"index.db", "index.db.attr", "index.db.serial"}

	for _, rm := range rms {
		if e = os.RemoveAll(filepath.Join(db.root, rm)); e != nil {
			return errors.Newf("failed to remove %s: %w", rm, e)
		}
	}

	return nil
}

func (db *database) getEntries() []certEntry {
	var entries []certEntry

	db.mutex.RLock()
	defer db.mutex.RUnlock()

	for _, entry := range db.entries {
		entries = append(entries, *entry)
	}

	return entries
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
	var e error
	var f *os.File
	var ok bool
	var tmp string = filepath.Join(db.root, "index.db.attr")

	// Create index.db.attr but for now there is no point in reading
	// this file back in.
	if ok, e = pathname.DoesExist(tmp); e != nil {
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
	var e error
	var entry *certEntry
	var f *os.File
	var ok bool
	var tmp string = filepath.Join(db.root, "index.db")

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
		if b, e = ioutil.ReadFile(tmp); e != nil {
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
		if b, e = ioutil.ReadFile(tmp); e != nil {
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
func (db *database) isRevoked(sn *big.Int) bool {
	var tmp string = hex.EncodeToString(sn.Bytes())

	db.mutex.RLock()
	defer db.mutex.RUnlock()

	db.initialize()

	for _, entry := range db.entries {
		if entry.sn == tmp {
			return entry.revoked
		}
	}

	return false
}

// nextSerialNumber will return the next available serial number that
// has not been used.
func (db *database) nextSerialNumber() *big.Int {
	return db.serialNumber
}

// revoke will update the PKI db to reflect that the cert with the
// specified serial number is revoked.
func (db *database) revoke(sn *big.Int) error {
	var e error
	var tmp string = hex.EncodeToString(sn.Bytes())

	db.mutex.Lock()
	defer db.mutex.Unlock()

	for _, entry := range db.entries {
		if entry.sn == tmp {
			if e = entry.revoke(); e != nil {
				return e
			}

			// Update files on disk
			return db.update()
		}
	}

	return errors.Newf("cert with serial number %s not found", tmp)
}

// undo will delete the previous entry in the PKI db.
func (db *database) undo() (string, error) {
	var e error
	var entry *certEntry

	// Lock while removing
	db.mutex.Lock()
	defer db.mutex.Unlock()

	// Return, if no entries to remove
	if len(db.entries) == 0 {
		return "", nil
	}

	// Get most recent entry
	entry = db.entries[len(db.entries)-1]

	// Delete
	db.entries = db.entries[:len(db.entries)-1]
	delete(db.seen, entry.sn)

	// Rollback serial number
	db.serialNumber.Sub(db.serialNumber, big.NewInt(1))

	// Update files on disk
	if e = db.update(); e != nil {
		return "", e
	}

	return entry.cn, nil
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
