package pki

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mjwhitta/errors"
	"github.com/mjwhitta/pathname"
)

func copyTo(root string, dir string, fn string) (e error) {
	var dst string
	var fr *os.File
	var fw *os.File
	var src string = filepath.Join(root, dir, fn)

	if strings.HasSuffix(fn, ".der") {
		if e = ensureExists("file", src); e != nil {
			// Backwards compatibility
			return nil // Old CertifyMe might not have created these
		}

		dst = filepath.Join(root, "ders", fn)
	} else if strings.HasSuffix(fn, ".pem") {
		if e = ensureExists("file", src); e != nil {
			return e
		}

		dst = filepath.Join(root, "pems", fn)
	}

	src = filepath.Clean(src)
	if fr, e = os.Open(src); e != nil {
		return errors.Newf("failed to open %s: %w", src, e)
	}
	defer func() {
		if e == nil {
			e = fr.Close()
		}
	}()

	dst = filepath.Clean(dst)
	if fw, e = os.Create(dst); e != nil {
		return errors.Newf("failed to create %s: %w", dst, e)
	}
	defer func() {
		if e == nil {
			e = fw.Close()
		}
	}()

	if _, e = io.Copy(fw, fr); e != nil {
		return errors.Newf("failed to copy %s to %s: %w", src, dst, e)
	}

	return nil
}

func createRWDir(dir string) error {
	var e error
	var ok bool

	if ok, e = pathname.DoesExist(dir); e != nil {
		return errors.Newf("directory %s not accessible: %w", dir, e)
	} else if ok {
		return nil
	}

	//nolint:mnd // u=rwx,go=-
	if e = os.MkdirAll(dir, 0o700); e != nil {
		e = errors.Newf("failed to create %s directory: %w", dir, e)
		return e
	}

	return nil
}

func deleteCert(root string, cn string) error {
	var e error
	var files []string = []string{
		filepath.Join(root, "certs", cn+".cert.der"),
		filepath.Join(root, "certs", cn+".cert.pem"),
	}

	for _, file := range files {
		// Delete file, if it exists
		if e = ensureExists("file", file); e != nil {
			continue // Ignore error, if file doesn't exist
		}

		if e = os.Remove(file); e != nil {
			e = errors.Newf("failed to delete cert %s: %w", file, e)
			return e
		}
	}

	return nil
}

func deleteCSR(root string, cn string) error {
	var e error
	var files []string = []string{
		filepath.Join(root, "csr", cn+".csr.der"),
		filepath.Join(root, "csr", cn+".csr.pem"),
	}

	for _, file := range files {
		// Delete file, if it exists
		if e = ensureExists("file", file); e != nil {
			continue // Ignore error, if file doesn't exist
		}

		if e = os.Remove(file); e != nil {
			return errors.Newf(
				"failed to delete cert request %s: %w",
				file,
				e,
			)
		}
	}

	return nil
}

func deleteKey(root string, cn string) error {
	var e error
	var files []string = []string{
		filepath.Join(root, "private", cn+".key.der"),
		filepath.Join(root, "private", cn+".key.pem"),
	}

	for _, file := range files {
		// Delete file, if it exists
		if e = ensureExists("file", file); e != nil {
			continue // Ignore error, if file doesn't exist
		}

		if e = os.Remove(file); e != nil {
			e = errors.Newf("failed to delete key %s: %w", file, e)
			return e
		}
	}

	return nil
}

func ensureExists(thetype string, fn string) error {
	if ok, e := pathname.DoesExist(fn); e != nil {
		return errors.Newf("%s %s not accessible: %w", thetype, fn, e)
	} else if !ok {
		return errors.Newf("%s %s not found", thetype, fn)
	}

	return nil
}

func existsOrCreate(fn string) error {
	if ok, e := pathname.DoesExist(fn); e != nil {
		return errors.Newf("directory %s not accessible: %w", fn, e)
	} else if !ok {
		return createRWDir(fn)
	}

	return nil
}

func getCA(root string) (*x509.Certificate, error) {
	return readCert(filepath.Join(root, "ca", "ca.cert.pem"))
}

func getCert(root string, cn string) (*x509.Certificate, error) {
	return readCert(filepath.Join(root, "certs", cn+".cert.pem"))
}

func getCSR(root, cn string) (*x509.CertificateRequest, error) {
	return readCSR(filepath.Join(root, "csr", cn+".csr.pem"))
}

func getKey(root string, cn string) (*rsa.PrivateKey, error) {
	return readKey(filepath.Join(root, "private", cn+".key.pem"))
}

func readCert(fn string) (*x509.Certificate, error) {
	var b []byte
	var block *pem.Block
	var cert *x509.Certificate
	var e error

	fn = filepath.Clean(fn)
	if b, e = os.ReadFile(fn); e != nil {
		return nil, errors.Newf("failed to read %s: %w", fn, e)
	}

	if block, _ = pem.Decode(b); block != nil {
		b = block.Bytes
	}

	if cert, e = x509.ParseCertificate(b); e != nil {
		return nil, errors.Newf("failed to parse cert %s: %w", fn, e)
	}

	return cert, nil
}

func readCSR(fn string) (*x509.CertificateRequest, error) {
	var b []byte
	var block *pem.Block
	var csr *x509.CertificateRequest
	var e error

	fn = filepath.Clean(fn)
	if b, e = os.ReadFile(fn); e != nil {
		return nil, errors.Newf("failed to read %s: %w", fn, e)
	}

	if block, _ = pem.Decode(b); block != nil {
		b = block.Bytes
	}

	if csr, e = x509.ParseCertificateRequest(b); e != nil {
		return nil, errors.Newf("failed to parse csr %s: %w", fn, e)
	}

	return csr, nil
}

func readKey(fn string) (*rsa.PrivateKey, error) {
	var b []byte
	var block *pem.Block
	var e error
	var key *rsa.PrivateKey

	fn = filepath.Clean(fn)
	if b, e = os.ReadFile(fn); e != nil {
		return nil, errors.Newf("failed to read %s: %w", fn, e)
	}

	if block, _ = pem.Decode(b); block != nil {
		b = block.Bytes
	}

	if key, e = x509.ParsePKCS1PrivateKey(b); e != nil {
		return nil, errors.Newf("failed to parse key %s: %w", fn, e)
	}

	return key, nil
}

func sigAlgForKey(key *rsa.PrivateKey) x509.SignatureAlgorithm {
	if key != nil {
		if key.N.BitLen() >= 4096 { //nolint:mnd // 512 * 8
			return x509.SHA512WithRSA
		} else if key.N.BitLen() >= 3072 { //nolint:mnd // 384 * 8
			return x509.SHA384WithRSA
		}

		return x509.SHA256WithRSA
	}

	return x509.UnknownSignatureAlgorithm
}

func writeCert(root string, cn string, cert *x509.Certificate) error {
	var b []byte
	var dir string = "certs"
	var e error
	var files []string

	if cert == nil {
		return errors.New("cert is nil")
	}

	if cert.IsCA {
		dir = "ca"
	}

	files = []string{
		filepath.Join(root, dir, cn+".cert.der"),
		filepath.Join(root, dir, cn+".cert.pem"),
	}

	for _, file := range files {
		b = []byte{}
		file = filepath.Clean(file)

		if strings.HasSuffix(file, ".der") {
			b = cert.Raw
		} else if strings.HasSuffix(file, ".pem") {
			b = pem.EncodeToMemory(
				&pem.Block{Bytes: cert.Raw, Type: "CERTIFICATE"},
			)
		}

		if len(b) > 0 {
			//nolint:mnd // u=rw,go=-
			if e = os.WriteFile(file, b, 0o600); e != nil {
				return errors.Newf(
					"failed to write cert %s: %w",
					file,
					e,
				)
			}
		}
	}

	return nil
}

func writeChain(root, cn string, certs ...*x509.Certificate) error {
	var b []byte
	var e error
	var files []string = []string{
		filepath.Join(root, "ders", cn+".chain.der"),
		filepath.Join(root, "pems", cn+".chain.pem"),
	}

	if len(certs) == 0 {
		return nil
	}

	for _, cert := range certs {
		if cert == nil {
			return errors.New("chain contains nil cert")
		}
	}

	for _, file := range files {
		b = []byte{}
		file = filepath.Clean(file)

		// Write each cert in chain
		if strings.HasSuffix(file, ".der") {
			for _, cert := range certs {
				b = append(b, cert.Raw...)
			}
		} else if strings.HasSuffix(file, ".pem") {
			for _, cert := range certs {
				b = append(
					b,
					pem.EncodeToMemory(
						&pem.Block{
							Bytes: cert.Raw,
							Type:  "CERTIFICATE",
						},
					)...,
				)
			}
		}

		if len(b) > 0 {
			//nolint:mnd // u=rw,go=-
			if e = os.WriteFile(file, b, 0o600); e != nil {
				return errors.Newf(
					"failed to write chain %s: %w",
					file,
					e,
				)
			}
		}
	}

	return nil
}

func writeCSR(root, cn string, csr *x509.CertificateRequest) error {
	var b []byte
	var e error
	var files []string = []string{
		filepath.Join(root, "csr", cn+".csr.der"),
		filepath.Join(root, "csr", cn+".csr.pem"),
	}

	if csr == nil {
		return errors.New("cert request is nil")
	}

	for _, file := range files {
		b = []byte{}
		file = filepath.Clean(file)

		if strings.HasSuffix(file, ".der") {
			b = csr.Raw
		} else if strings.HasSuffix(file, ".pem") {
			b = pem.EncodeToMemory(
				&pem.Block{
					Bytes: csr.Raw,
					Type:  "CERTIFICATE REQUEST",
				},
			)
		}

		if len(b) > 0 {
			//nolint:mnd // u=rw,go=-
			if e = os.WriteFile(file, b, 0o600); e != nil {
				return errors.Newf(
					"failed to write cert request %s: %w",
					file,
					e,
				)
			}
		}
	}

	return nil
}

func writeKey(root string, cn string, key *rsa.PrivateKey) error {
	var b []byte
	var e error
	var files []string = []string{
		filepath.Join(root, "private", cn+".key.der"),
		filepath.Join(root, "private", cn+".key.pem"),
	}

	if key == nil {
		return errors.New("key is nil")
	}

	for _, file := range files {
		b = []byte{}
		file = filepath.Clean(file)

		if strings.HasSuffix(file, ".der") {
			b = x509.MarshalPKCS1PrivateKey(key)
		} else if strings.HasSuffix(file, ".pem") {
			b = pem.EncodeToMemory(
				&pem.Block{
					Bytes: x509.MarshalPKCS1PrivateKey(key),
					Type:  "RSA PRIVATE KEY",
				},
			)
		}

		if len(b) > 0 {
			//nolint:mnd // u=r,go=-
			if e = os.WriteFile(file, b, 0o400); e != nil {
				return errors.Newf(
					"failed to write key %s: %w",
					file,
					e,
				)
			}
		}
	}

	return nil
}

func writeKeyPair(
	root string,
	cn string,
	cert *x509.Certificate,
	key *rsa.PrivateKey,
) error {
	var b []byte
	var e error
	var files []string = []string{
		filepath.Join(root, "ders", cn+".der"),
		filepath.Join(root, "pems", cn+".pem"),
	}

	if cert == nil {
		return errors.New("cert is nil")
	} else if key == nil {
		return errors.New("key is nil")
	}

	for _, file := range files {
		b = []byte{}
		file = filepath.Clean(file)

		if strings.HasSuffix(file, ".der") {
			b = cert.Raw
			b = append(b, x509.MarshalPKCS1PrivateKey(key)...)
		} else if strings.HasSuffix(file, ".pem") {
			b = append(
				pem.EncodeToMemory(
					&pem.Block{Bytes: cert.Raw, Type: "CERTIFICATE"},
				),
				pem.EncodeToMemory(
					&pem.Block{
						Bytes: x509.MarshalPKCS1PrivateKey(key),
						Type:  "RSA PRIVATE KEY",
					},
				)...,
			)
		}

		if len(b) > 0 {
			//nolint:mnd // u=r,go=-
			if e = os.WriteFile(file, b, 0o600); e != nil {
				return errors.Newf(
					"failed to write keypair %s: %w",
					file,
					e,
				)
			}
		}
	}

	return nil
}
