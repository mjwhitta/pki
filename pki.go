// Package pki provides a platform-independent means of generating PKI
// infrastructure. It will accept a filepath (directory) and Cfg then
// create a Certificate Authority (CA) for signing client or server
// X509 Certificates. Below is some sample code to create a default
// self-signed PKI:
//
//	var e error
//	var p *pki.PKI
//
//	if p, e = pki.New("/pki/root/dir", pki.NewCfg()); e != nil {
//	    panic(e)
//	}
//
// From there, client and server Certificates can be created or
// Certificate Signing Requests (CSRs) can be imported and used to
// generate a Certificate for a third-party.
//
// The PKI infrastructure contains a built-in database for tracking
// generated Certificates and if/when they expired or were revoked.
package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/mjwhitta/errors"
)

// PKI is a structure that contains the PKI config, key size for
// generated Certificates, and the root of the PKI infrastructure.
type PKI struct {
	Cfg     *Cfg
	KeySize int
	Root    string

	ca  *x509.Certificate
	db  *database
	key *rsa.PrivateKey
}

// New will return a pointer to a new PKI instance as well as
// initialized the PKI infrastructure on disk.
func New(root string, cfg *Cfg) (*PKI, error) {
	var db *database
	var e error
	var p *PKI

	if e = existsOrCreate(root); e != nil {
		return nil, e
	}

	if cfg == nil {
		return nil, errors.New("empty PKI config provided")
	}

	if db, e = newDatabase(root); e != nil {
		return nil, e
	}

	p = &PKI{
		Cfg:     cfg,
		db:      db,
		KeySize: 4096,
		Root:    root,
	}

	if e = p.initialize(); e != nil {
		return nil, e
	}

	return p, nil
}

// CreateCA will create a new self-signed CA Certificate and return
// the Certificate with its associated private key. If a CA and key
// already exist on disk, they will be parsed and returned instead.
func (p *PKI) CreateCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	var e error
	var pubkey any // *rsa.PublicKey

	// Use existing key, if found, otherwise create
	if p.key, e = p.createOrGetKey("ca"); e != nil {
		return nil, nil, e
	}

	// Use existing CA, if found
	if p.HasCA() {
		if p.ca, e = getCA(p.Root); e != nil {
			return nil, nil, e
		}
	}

	if p.ca == nil {
		// Create CA file
		pubkey = &p.key.PublicKey
		p.ca, e = p.createCert(nil, "ca", nil, pubkey, CACert)
		if e != nil {
			return nil, nil, e
		}
	}

	return p.ca, p.key, nil
}

// CreateCertFor will create a Certificate for the specified
// CommonName, signed by the PKI's CA. The new Certificate and its
// associated private key will be returned. If a Certificate and key
// already exist on disk, they will be parsed and returned instead.
// See CertType for supported Certificate types.
func (p *PKI) CreateCertFor(
	cn string, certType CertType, alts ...string,
) (*x509.Certificate, *rsa.PrivateKey, error) {
	var cert *x509.Certificate
	var csr *x509.CertificateRequest
	var e error
	var key *rsa.PrivateKey

	if cn == "" {
		return nil, nil, errNoCN
	}

	if p.ca == nil {
		if _, _, e = p.CreateCA(); e != nil {
			return nil, nil, e
		}
	}

	if !p.HasCSRFor(cn) || p.HasKeyFor(cn) {
		// Use existing key, if found, otherwise create
		if key, e = p.createOrGetKey(cn); e != nil {
			return nil, nil, e
		}
	}

	// Use existing cert request, if found, otherwise create
	if csr, e = p.createOrGetCSR(cn, key, alts...); e != nil {
		return nil, nil, e
	}

	// Use existing cert, if found, otherwise create
	cert, e = p.createOrGetCert(cn, csr, csr.PublicKey, certType)
	if e != nil {
		return nil, nil, e
	}

	return cert, key, nil
}

func (p *PKI) createCert(
	ca *x509.Certificate,
	cn string,
	csr *x509.CertificateRequest,
	pubkey any, // *rsa.PublicKey
	certType CertType,
) (*x509.Certificate, error) {
	var after time.Time
	var b []byte
	var before time.Time
	var cert *x509.Certificate
	var e error
	var extUsage []x509.ExtKeyUsage
	var hash [sha1.Size]byte
	var sn *big.Int
	var usage x509.KeyUsage

	// Hash public key for future use
	if b, e = x509.MarshalPKIXPublicKey(pubkey); e != nil {
		return nil, errors.Newf("failed to hash pubkey: %w", e)
	}
	hash = sha1.Sum(b)

	// Setup some shared params
	before = time.Now()

	switch certType {
	case CACert:
		after = before.AddDate(0, 0, p.Cfg.CADaysValid)

		extUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		}

		// Use public key's hash as serial number
		sn = big.NewInt(0).SetBytes(hash[:])

		usage |= x509.KeyUsageCertSign
		usage |= x509.KeyUsageCRLSign
		usage |= x509.KeyUsageDigitalSignature

		// Create CA template
		ca = &x509.Certificate{
			AuthorityKeyId:        hash[:],
			BasicConstraintsValid: true,
			ExtKeyUsage:           extUsage,
			IsCA:                  true,
			KeyUsage:              usage,
			NotAfter:              after,
			NotBefore:             before,
			SerialNumber:          sn,
			SignatureAlgorithm:    sigAlgForKey(p.key),
			Subject:               p.Cfg.Subject(),
			SubjectKeyId:          hash[:],
		}

		cert = ca
	default:
		// Validate signature
		if csr == nil {
			e = errors.Newf("no cert request provided for %s", cn)
			return nil, e
		} else if e = csr.CheckSignature(); e != nil {
			return nil, e
		}

		switch certType {
		case ClientCert:
			after = before.AddDate(0, 0, p.Cfg.CertDaysValid)

			extUsage = []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageEmailProtection,
			}

			// Get serial number from db
			if sn, e = p.db.nextSerialNumber(); e != nil {
				return nil, e
			}

			usage |= x509.KeyUsageContentCommitment // Non Repudiation
			usage |= x509.KeyUsageDigitalSignature
			usage |= x509.KeyUsageKeyEncipherment
		case ServerCert:
			after = before.AddDate(0, 0, p.Cfg.CertDaysValid)

			extUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

			// Get serial number from db
			if sn, e = p.db.nextSerialNumber(); e != nil {
				return nil, e
			}

			usage |= x509.KeyUsageDigitalSignature
			usage |= x509.KeyUsageKeyEncipherment
		}

		// Create cert template
		cert = &x509.Certificate{
			BasicConstraintsValid: true,
			DNSNames:              csr.DNSNames,
			ExtKeyUsage:           extUsage,
			IPAddresses:           csr.IPAddresses,
			KeyUsage:              usage,
			NotAfter:              after,
			NotBefore:             before,
			SerialNumber:          sn,
			SignatureAlgorithm:    csr.SignatureAlgorithm,
			Subject:               csr.Subject,
			SubjectKeyId:          hash[:],
		}
	}

	// Create self-signed CA or cert from template
	b, e = x509.CreateCertificate(
		rand.Reader,
		cert, // template
		ca,   // parent
		pubkey,
		p.key,
	)
	if e != nil {
		return nil, errors.Newf("failed to generate cert: %w", e)
	}

	if cert, e = x509.ParseCertificate(b); e != nil {
		return nil, errors.Newf("failed to parse cert: %w", e)
	}

	// Write cert
	if e = writeCert(p.Root, cn, cert); e != nil {
		return nil, e
	}

	return cert, nil
}

// CreateCSRFor will create a Certificate request for the specified
// CommonName, signed by the provided private key.
func (p *PKI) CreateCSRFor(
	cn string, key *rsa.PrivateKey, alts ...string,
) (*x509.CertificateRequest, error) {
	var b []byte
	var csr *x509.CertificateRequest
	var dns []string = []string{cn}
	var e error
	var ips []net.IP
	var tmp net.IP

	if cn == "" {
		return nil, errNoCN
	}

	if key == nil {
		return nil, errors.New("no private key provided")
	}

	// Parse alts
	for _, alt := range alts {
		if tmp = net.ParseIP(alt); tmp != nil {
			ips = append(ips, tmp)
		} else {
			dns = append(dns, alt)
		}
	}

	// Create cert request template
	csr = &x509.CertificateRequest{
		DNSNames:           dns,
		IPAddresses:        ips,
		SignatureAlgorithm: sigAlgForKey(key),
		Subject:            p.Cfg.Subject(cn),
	}

	// Create request to sign by CA
	b, e = x509.CreateCertificateRequest(
		rand.Reader,
		csr, // template
		key,
	)
	if e != nil {
		return nil, errors.Newf("failed to generate request: %w", e)
	}

	if csr, e = x509.ParseCertificateRequest(b); e != nil {
		return nil, errors.Newf("failed to parse cert request: %w", e)
	}

	// Write cert request
	if e = writeCSR(p.Root, cn, csr); e != nil {
		return nil, e
	}

	return csr, nil
}

func (p *PKI) createOrGetCert(
	cn string,
	csr *x509.CertificateRequest,
	pubkey any, // *rsa.PublicKey
	certType CertType,
) (*x509.Certificate, error) {
	var cert *x509.Certificate
	var e error

	// Use existing cert, if found
	if p.HasCertFor(cn) {
		if cert, e = p.db.getCertFor(cn, true); e != nil {
			return nil, e
		}
	}

	if cert == nil {
		// Create cert
		cert, e = p.createCert(p.ca, cn, csr, pubkey, certType)
		if e != nil {
			return nil, e
		}

		// Update db with new cert
		if e = p.db.add(cert); e != nil {
			return nil, e
		}
	}

	return cert, nil
}

func (p *PKI) createOrGetCSR(
	cn string, key *rsa.PrivateKey, alts ...string,
) (*x509.CertificateRequest, error) {
	var csr *x509.CertificateRequest
	var e error

	// Use existing cert request, if found
	if p.HasCSRFor(cn) {
		if csr, e = getCSR(p.Root, cn); e != nil {
			return nil, e
		}
	}

	if csr == nil {
		// Create cert request
		if csr, e = p.CreateCSRFor(cn, key, alts...); e != nil {
			return nil, e
		}
	}

	return csr, nil
}

func (p *PKI) createOrGetKey(cn string) (*rsa.PrivateKey, error) {
	var e error
	var key *rsa.PrivateKey

	// Use existing key, if found
	if p.HasKeyFor(cn) {
		if key, e = getKey(p.Root, cn); e != nil {
			return nil, e
		}
	}

	if key == nil {
		// Create CA key
		if key, e = p.CreateRSAKeyFor(cn); e != nil {
			return nil, e
		}
	}

	return key, nil
}

// CreateRSAKeyFor will create an RSA private key for the specified
// CommonName.
func (p *PKI) CreateRSAKeyFor(cn string) (*rsa.PrivateKey, error) {
	var e error
	var key *rsa.PrivateKey

	if cn == "" {
		return nil, errNoCN
	}

	// Create private key
	if key, e = rsa.GenerateKey(rand.Reader, p.KeySize); e != nil {
		return nil, errors.Newf("failed to generate privkey: %w", e)
	}

	// Write key
	if e = writeKey(p.Root, cn, key); e != nil {
		return nil, e
	}

	return key, nil
}

// Erase will erase all PKI related files and directories. Be careful.
// This is non-reversable.
func (p *PKI) Erase() error {
	var e error
	var dirs []string = []string{
		"ca",
		"certs",
		"csr",
		"ders",
		"pems",
		"private",
	}

	for _, dir := range dirs {
		if e = os.RemoveAll(filepath.Join(p.Root, dir)); e != nil {
			return errors.Newf("failed to remove %s: %w", dir, e)
		}
	}

	p.ca = nil
	p.db.erase()
	p.key = nil

	return nil
}

// Fingerprint will return the sha1 hash of the provided Certificate.
func (p *PKI) Fingerprint(cert *x509.Certificate) string {
	var hash [sha1.Size]byte

	if cert == nil {
		return ""
	}

	hash = sha1.Sum(cert.Raw)

	return hex.EncodeToString(hash[:])
}

// FingerprintFor will return the sha1 hash of the Certificate for the
// specified CommonName, should it exist. If the Certificate does not
// exist or is revoked, it will return empty string.
func (p *PKI) FingerprintFor(cn string) string {
	var cert *x509.Certificate
	var e error

	if !p.HasCertFor(cn) {
		return ""
	}

	if cert, e = p.db.getCertFor(cn, true); e != nil {
		return ""
	}

	return p.Fingerprint(cert)
}

// GetCAFile will return the filepath for the CA. There is no
// guarantee that the file exists. Use HasCA() first.
func (p *PKI) GetCAFile() string {
	return filepath.Join(p.Root, "ca", "ca.cert.pem")
}

// GetCertFileFor will return the filepath for the Certificate. There
// is no guarantee that the file exists. Use HasCertFor() first.
func (p *PKI) GetCertFileFor(cn string) string {
	if cn == "" {
		return ""
	}

	return filepath.Join(p.Root, "certs", cn+".cert.pem")
}

// GetCSRFileFor will return the filepath for the CSR. There is no
// guarantee that the file exists. Use HasCSRFor() first.
func (p *PKI) GetCSRFileFor(cn string) string {
	if cn == "" {
		return ""
	}

	return filepath.Join(p.Root, "csr", cn+".csr.pem")
}

// GetKeyFileFor will return the filepath for the private key. There
// is no guarantee that the file exists. Use HasKeyFor() first.
func (p *PKI) GetKeyFileFor(cn string) string {
	if cn == "" {
		return ""
	}

	return filepath.Join(p.Root, "private", cn+".key.pem")
}

// HasCA will return whether or not a CA already exists. This only
// checks if the file exists on disk. It does not validate that the
// file contains a valid Certificate.
func (p *PKI) HasCA() bool {
	return ensureExists("file", p.GetCAFile()) == nil
}

// HasCertFor will return whether or not a Certificate for the
// specified CommonName already exists. This only checks if the file
// exists on disk. It does not validate that the file contains a valid
// Certificate.
func (p *PKI) HasCertFor(cn string) bool {
	if cn == "" {
		return false
	} else if _, e := p.db.getEntry(cn); e != nil {
		return false
	}

	return true
}

// HasCSRFor will return whether or not a CSR for the specified
// CommonName already exists. This only checks if the file exists on
// disk. It does not validate that the file contains a valid CSR.
func (p *PKI) HasCSRFor(cn string) bool {
	if cn == "" {
		return false
	}

	return ensureExists("file", p.GetCSRFileFor(cn)) == nil
}

// HasKeyFor will return whether or not a private key for the
// specified CommonName already exists. This only checks if the file
// exists on disk. It does not validate that the file contains a valid
// private key.
func (p *PKI) HasKeyFor(cn string) bool {
	if cn == "" {
		return false
	}

	return ensureExists("file", p.GetKeyFileFor(cn)) == nil
}

// HasSigned will return whether or not the provided Certificate has
// been signed by the PKI's CA.
func (p *PKI) HasSigned(cert *x509.Certificate) bool {
	if (cert == nil) || (p.ca == nil) {
		return false
	}

	return cert.CheckSignatureFrom(p.ca) == nil
}

// ImportCSR will read the provided CSR and attempt import it into
// the PKI. If the embedded CommonName already has a Certificate or
// CSR, an error will be returned.
func (p *PKI) ImportCSR(fn string) error {
	var cn string
	var csr *x509.CertificateRequest
	var e error

	// Read in cert request
	if csr, e = readCSR(fn); e != nil {
		return e
	}

	// Validate the cert request has a CN
	if cn = csr.Subject.CommonName; cn == "" {
		return errors.Newf("cert request %s has no CommonName", fn)
	}

	if p.HasCertFor(cn) {
		return errors.Newf("%s already has a cert", cn)
	} else if p.HasCSRFor(cn) {
		return errors.Newf("%s already has a cert request", cn)
	}

	// Write cert request to file
	if e = writeCSR(p.Root, cn, csr); e != nil {
		return e
	}

	return nil
}

// initialize will create all PKI related directories.
func (p *PKI) initialize() error {
	var e error
	var dirs []string = []string{
		"ca",
		"certs",
		"csr",
		"ders",
		"pems",
		"private",
	}

	for _, dir := range dirs {
		if e = createRWDir(filepath.Join(p.Root, dir)); e != nil {
			return e
		}
	}

	return nil
}

// IsExpired will return whether or not the specified Certificate has
// expired. This takes a Certificate b/c a CommonName is not enough
// info with "unique_subject = no".
func (p *PKI) IsExpired(cert *x509.Certificate) bool {
	return time.Now().After(cert.NotAfter)
}

// IsRevoked will return whether or not the specified Certificate has
// been revoked. This takes a Certificate b/c a CommonName is not
// enough info with "unique_subject = no".
func (p *PKI) IsRevoked(cert *x509.Certificate) (bool, error) {
	return p.db.isRevoked(cert.SerialNumber)
}

// RevokeCert will revoke the provided Certificate.
func (p *PKI) RevokeCert(cert *x509.Certificate) error {
	var cn string
	var e error

	if cert == nil {
		return errNoCert
	}

	// Revoke cert
	if cn, e = p.db.revokeSN(cert.SerialNumber); e != nil {
		return e
	}

	// Delete files, but don't throw error here b/c files may have
	// been manually deleted.
	deleteCert(p.Root, cn)
	deleteCSR(p.Root, cn)
	deleteKey(p.Root, cn)

	return nil
}

// RevokeCertFor will revoke the oldest Certificate with the specified
// CommonName and return it for any post-processing, such as manually
// maintaining a Certificate Revocation List (CRL).
func (p *PKI) RevokeCertFor(cn string) (*x509.Certificate, error) {
	var cert *x509.Certificate
	var e error

	if cn == "" {
		return nil, errNoCN
	}

	// Revoke cert
	if cert, e = p.db.revokeCN(cn); e != nil {
		return nil, e
	}

	// Delete files, but don't throw error here b/c files may have
	// been manually deleted.
	deleteCert(p.Root, cn)
	deleteCSR(p.Root, cn)
	deleteKey(p.Root, cn)

	return cert, nil
}

// Sync will make sure that all ders/pems are mirrored in the
// associated directories for convenient access.
func (p *PKI) Sync() error {
	var cert *x509.Certificate
	var e error
	var entries []*certEntry

	// Reset ders/pems subdirectories
	if e = p.unsync(); e != nil {
		return e
	}

	// Nothing to sync
	if !p.HasCA() {
		return nil
	}

	// Sync CA
	if p.ca == nil {
		if p.ca, e = getCA(p.Root); e != nil {
			return e
		}
	}

	if e = p.syncCert(p.ca); e != nil {
		return e
	}

	// Sync certs and associated keys
	if entries, e = p.db.getEntries(); e != nil {
		return e
	}

	for _, ce := range entries {
		// Skip expired and revoked certs
		if ce.expired || ce.revoked {
			continue
		}

		// Skip certs that are not tracked
		if ce.file == "unknown" {
			continue
		}

		// Read cert
		if cert, e = p.db.getCertFor(ce.cn, false); e != nil {
			return e
		}

		// Sync cert, key, and chain/keypair to ders/pems directory
		if e = p.syncCert(cert); e != nil {
			return e
		}
	}

	return nil
}

func (p *PKI) syncCert(cert *x509.Certificate) error {
	var cn string
	var dir string = "certs"
	var e error
	var key *rsa.PrivateKey

	// If cert is nil, this would mean that a Certificate failed to
	// generate. In this case, we still want to sync other valid
	// files. Therefore, do not return an error.
	if cert == nil {
		return nil
	}

	// Store CN
	cn = cert.Subject.CommonName

	if cert.IsCA {
		cn = "ca"
		dir = "ca"
	}

	for _, ext := range []string{"der", "pem"} {
		// Copy cert
		if e = copyTo(p.Root, dir, cn+".cert."+ext); e != nil {
			return e
		}

		// Copy key
		if e = copyTo(p.Root, "private", cn+".key."+ext); e != nil {
			return e
		}

		// Done, if CA
		if cert.IsCA {
			continue
		}

		for _, usage := range cert.ExtKeyUsage {
			switch usage {
			case x509.ExtKeyUsageClientAuth:
				// Create keypair, if key exists
				if p.HasKeyFor(cn) {
					if key, e = getKey(p.Root, cn); e != nil {
						return e
					}

					if key == nil {
						continue
					}

					e = writeKeyPair(p.Root, cn, cert, key)
					if e != nil {
						return e
					}
				}
			case x509.ExtKeyUsageServerAuth:
				// Create cert chain
				if e = writeChain(p.Root, cn, cert, p.ca); e != nil {
					return e
				}
			}
		}
	}

	return nil
}

// Undo will rollback the PKI database and delete the most recently
// generated Certificate and its associated CSR and private key.
func (p *PKI) Undo() error {
	var cn string
	var e error

	// Rollback db
	if cn, e = p.db.undo(); e != nil {
		return e
	} else if cn == "" {
		// No files to delete, if no entry in db
		return errors.New("no entries to rollback")
	}

	// Delete files
	deleteCert(p.Root, cn)
	if p.HasCSRFor(cn) {
		if e = deleteCSR(p.Root, cn); e != nil {
			return e
		}
	}
	if p.HasKeyFor(cn) {
		if e = deleteKey(p.Root, cn); e != nil {
			return e
		}
	}

	return nil
}

func (p *PKI) unsync() error {
	var e error
	var dirs []string = []string{
		"ders",
		"pems",
	}

	for _, dir := range dirs {
		if e = os.RemoveAll(filepath.Join(p.Root, dir)); e != nil {
			return errors.Newf("failed to remove %s: %w", dir, e)
		}

		if e = createRWDir(filepath.Join(p.Root, dir)); e != nil {
			return e
		}
	}

	return nil
}
