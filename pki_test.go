//nolint:godoclint // These are tests
package pki_test

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/mjwhitta/pki"
	assert "github.com/stretchr/testify/require"
)

type cnFunc func(cn string) string

func setup(t *testing.T, dirs ...string) *pki.PKI {
	t.Helper()

	var dir string = t.TempDir()
	var e error
	var p *pki.PKI

	if len(dirs) != 0 {
		dir = dirs[0]
	}

	p, e = pki.New(dir, pki.NewCfg())
	assert.NoError(t, e)
	assert.NotNil(t, p)

	p.Cfg.Country("US")
	p.KeySize = 1024

	return p
}

func TestCreateCA(t *testing.T) {
	t.Run(
		"ErrorFailKeyCreation",
		func(t *testing.T) {
			var ca *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			if runtime.GOOS == "windows" {
				t.Skip("runtime OS not supported")
			}

			// Ensure not writable
			defer func() {
				//nolint:gosec // G302 - false positive, this is a dir
				_ = os.Chmod(filepath.Join(p.Root, "private"), 0o700)
			}()
			//nolint:gosec // G302 - 0o500 is less than 0o600...
			e = os.Chmod(filepath.Join(p.Root, "private"), 0o500)
			assert.NoError(t, e)

			ca, k, e = p.CreateCA()
			assert.Error(t, e)
			assert.Nil(t, ca)
			assert.Nil(t, k)
		},
	)

	t.Run(
		"ErrorFailCACreation",
		func(t *testing.T) {
			var ca *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			if runtime.GOOS == "windows" {
				t.Skip("runtime OS not supported")
			}

			// Ensure not writable
			defer func() {
				//nolint:gosec // G302 - false positive, this is a dir
				_ = os.Chmod(filepath.Join(p.Root, "ca"), 0o700)
			}()
			//nolint:gosec // G302 - 0o500 is less than 0o600...
			e = os.Chmod(filepath.Join(p.Root, "ca"), 0o500)
			assert.NoError(t, e)

			ca, k, e = p.CreateCA()
			assert.Error(t, e)
			assert.Nil(t, ca)
			assert.Nil(t, k)
		},
	)

	t.Run(
		"ErrorFailReadExistingCA",
		func(t *testing.T) {
			var ca *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			ca, k, e = p.CreateCA()
			assert.NoError(t, e)
			assert.NotNil(t, ca)
			assert.NotNil(t, k)

			// Create empty file
			_, e = os.Create(p.GetCAFile())
			assert.NoError(t, e)

			ca, k, e = p.CreateCA()
			assert.Error(t, e)
			assert.Nil(t, ca)
			assert.Nil(t, k)
		},
	)

	t.Run(
		"Success",
		func(t *testing.T) {
			var ca *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			ca, k, e = p.CreateCA()
			assert.NoError(t, e)
			assert.NotNil(t, ca)
			assert.NotNil(t, k)
		},
	)
}

func TestCreateCertFor(t *testing.T) {
	type testData struct {
		alts     []string
		certType pki.CertType
		cn       string
	}

	var p *pki.PKI = setup(t)
	var tests map[string]testData = map[string]testData{
		"CreateClientCert": {
			alts:     []string{},
			certType: pki.ClientCert,
			cn:       "user",
		},
		"GetClientCert": {
			alts:     []string{},
			certType: pki.ClientCert,
			cn:       "user",
		},
		"CreateServerCert": {
			alts:     []string{"localhost", "127.0.0.1"},
			certType: pki.ServerCert,
			cn:       "example.com",
		},
	}

	t.Run(
		"ErrorFailReadExistingCA",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			// Create empty file
			_, e = os.Create(p.GetCAFile())
			assert.NoError(t, e)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.Error(t, e)
			assert.Nil(t, c)
			assert.Nil(t, k)
		},
	)

	t.Run(
		"ErrorFailReadExistingKey",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.NoError(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			// Make writable
			e = os.Chmod(p.GetKeyFileFor("example.com"), 0o600)
			assert.NoError(t, e)

			// Create empty file
			_, e = os.Create(p.GetKeyFileFor("example.com"))
			assert.NoError(t, e)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.Error(t, e)
			assert.Nil(t, c)
			assert.Nil(t, k)
		},
	)

	t.Run(
		"ErrorFailReadExistingCSR",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.NoError(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			// Create empty file
			_, e = os.Create(p.GetCSRFileFor("example.com"))
			assert.NoError(t, e)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.Error(t, e)
			assert.Nil(t, c)
			assert.Nil(t, k)
		},
	)

	t.Run(
		"ErrorFailReadExistingCert",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.NoError(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			// Create empty file
			_, e = os.Create(p.GetCertFileFor("example.com"))
			assert.NoError(t, e)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.Error(t, e)
			assert.Nil(t, c)
			assert.Nil(t, k)
		},
	)

	t.Run(
		"ErrorNoCN",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey

			c, k, e = p.CreateCertFor("", pki.ServerCert)
			assert.Error(t, e)
			assert.Nil(t, c)
			assert.Nil(t, k)
		},
	)

	for test, data := range tests {
		t.Run(
			test,
			func(t *testing.T) {
				var c *x509.Certificate
				var e error
				var k *rsa.PrivateKey

				c, k, e = p.CreateCertFor(data.cn, data.certType)
				assert.NoError(t, e)
				assert.NotNil(t, c)
				assert.NotNil(t, k)
			},
		)
	}
}

func TestCreateCSRFor(t *testing.T) {
	t.Run(
		"ErrorNoCN",
		func(t *testing.T) {
			var csr *x509.CertificateRequest
			var e error
			var p *pki.PKI = setup(t)

			csr, e = p.CreateCSRFor("", nil)
			assert.Error(t, e)
			assert.Nil(t, csr)
		},
	)

	t.Run(
		"ErrorNilKey",
		func(t *testing.T) {
			var csr *x509.CertificateRequest
			var e error
			var p *pki.PKI = setup(t)

			csr, e = p.CreateCSRFor("example.com", nil)
			assert.Error(t, e)
			assert.Nil(t, csr)
		},
	)

	t.Run(
		"ErrorFailWriteCSR",
		func(t *testing.T) {
			var csr *x509.CertificateRequest
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			if runtime.GOOS == "windows" {
				t.Skip("runtime OS not supported")
			}

			k, e = p.CreateRSAKeyFor("example.com")
			assert.NoError(t, e)
			assert.NotNil(t, k)

			// Ensure not writable
			defer func() {
				//nolint:gosec // G302 - false positive, this is a dir
				_ = os.Chmod(filepath.Join(p.Root, "csr"), 0o700)
			}()
			//nolint:gosec // G302 - 0o500 is less than 0o600...
			e = os.Chmod(filepath.Join(p.Root, "csr"), 0o500)
			assert.NoError(t, e)

			csr, e = p.CreateCSRFor("example.com", k)
			assert.Error(t, e)
			assert.Nil(t, csr)
		},
	)

	t.Run(
		"Success",
		func(t *testing.T) {
			var csr *x509.CertificateRequest
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			k, e = p.CreateRSAKeyFor("example.com")
			assert.NoError(t, e)
			assert.NotNil(t, k)

			csr, e = p.CreateCSRFor("example.com", k)
			assert.NoError(t, e)
			assert.NotNil(t, csr)
		},
	)
}

func TestCreateRSAKeyFor(t *testing.T) {
	t.Run(
		"ErrorFailWriteKey",
		func(t *testing.T) {
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			if runtime.GOOS == "windows" {
				t.Skip("runtime OS not supported")
			}

			// Ensure not writable
			defer func() {
				//nolint:gosec // G302 - false positive, this is a dir
				_ = os.Chmod(filepath.Join(p.Root, "private"), 0o700)
			}()
			//nolint:gosec // G302 - 0o500 is less than 0o600...
			e = os.Chmod(filepath.Join(p.Root, "private"), 0o500)
			assert.NoError(t, e)

			k, e = p.CreateRSAKeyFor("example.com")
			assert.Error(t, e)
			assert.Nil(t, k)
		},
	)

	t.Run(
		"ErrorNoCN",
		func(t *testing.T) {
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			k, e = p.CreateRSAKeyFor("")
			assert.Error(t, e)
			assert.Nil(t, k)
		},
	)

	t.Run(
		"Success",
		func(t *testing.T) {
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			k, e = p.CreateRSAKeyFor("example.com")
			assert.NoError(t, e)
			assert.NotNil(t, k)
		},
	)
}

func TestErase(t *testing.T) {
	t.Run(
		"ErrorFailPKIErase",
		func(t *testing.T) {
			var e error
			var p *pki.PKI = setup(t)

			if runtime.GOOS == "windows" {
				t.Skip("runtime OS not supported")
			}

			// Ensure not writable
			defer func() {
				//nolint:gosec // G302 - false positive, this is a dir
				_ = os.Chmod(p.Root, 0o700)
			}()
			//nolint:gosec // G302 - 0o500 is less than 0o600...
			e = os.Chmod(p.Root, 0o500)
			assert.NoError(t, e)

			e = p.Erase()
			assert.Error(t, e)
		},
	)

	t.Run(
		"Success",
		func(t *testing.T) {
			var e error
			var p *pki.PKI = setup(t)

			e = p.Erase()
			assert.NoError(t, e)
		},
	)
}

func TestFingerprint(t *testing.T) {
	t.Run(
		"ErrorNoCN",
		func(t *testing.T) {
			var p *pki.PKI = setup(t)

			assert.Empty(t, p.Fingerprint(nil))
		},
	)

	t.Run(
		"Success",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var fp string
			var hash [sha256.Size]byte
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.NoError(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			hash = sha256.Sum256(c.Raw)
			fp = hex.EncodeToString(hash[:])
			assert.Equal(t, fp, p.Fingerprint(c))
		},
	)
}

func TestFingerprintFor(t *testing.T) {
	t.Run(
		"ErrorNoCN",
		func(t *testing.T) {
			var p *pki.PKI = setup(t)

			assert.Empty(t, p.FingerprintFor(""))
		},
	)

	t.Run(
		"ErrorFailReadExistingCert",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.NoError(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			// Create empty file
			_, e = os.Create(p.GetCertFileFor("example.com"))
			assert.NoError(t, e)

			assert.Empty(t, p.FingerprintFor("example.com"))
		},
	)

	t.Run(
		"Success",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var fp string
			var hash [sha256.Size]byte
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.NoError(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			hash = sha256.Sum256(c.Raw)
			fp = hex.EncodeToString(hash[:])
			assert.Equal(t, fp, p.FingerprintFor("example.com"))
		},
	)
}

func TestGetFiles(t *testing.T) {
	var p *pki.PKI = setup(t)
	var tests map[string]cnFunc = map[string]cnFunc{
		"CertNoCN": p.GetCertFileFor,
		"CSRNoCN":  p.GetCSRFileFor,
		"KeyNoCN":  p.GetKeyFileFor,
	}

	for test, f := range tests {
		t.Run(
			test,
			func(t *testing.T) {
				var fn string = f("")

				assert.Empty(t, fn)
			},
		)
	}

	tests = map[string]cnFunc{
		"SuccessCert": p.GetCertFileFor,
		"SuccessCSR":  p.GetCSRFileFor,
		"SuccessKey":  p.GetKeyFileFor,
	}

	for test, f := range tests {
		t.Run(
			test,
			func(t *testing.T) {
				var fn string = f("example.com")

				assert.NotEmpty(t, fn)
			},
		)
	}
}

func TestHasCertFor(t *testing.T) {
	var p *pki.PKI = setup(t)

	assert.False(t, p.HasCertFor(""))
}

func TestHasCSR(t *testing.T) {
	var p *pki.PKI = setup(t)

	assert.False(t, p.HasCSRFor(""))
}

func TestHasKeyFor(t *testing.T) {
	var p *pki.PKI = setup(t)

	assert.False(t, p.HasKeyFor(""))
}

func TestHasSigned(t *testing.T) {
	t.Run(
		"FalseNil",
		func(t *testing.T) {
			var e error
			var p *pki.PKI = setup(t)
			var signed bool

			_, _, e = p.CreateCA()
			assert.NoError(t, e)

			signed = p.HasSigned(nil)
			assert.False(t, signed)
		},
	)

	t.Run(
		"FalseNoCA",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var p1 *pki.PKI = setup(t)
			var p2 *pki.PKI = setup(t)
			var signed bool

			c, _, e = p2.CreateCertFor("example.com", pki.ServerCert)
			assert.NoError(t, e)
			assert.NotNil(t, c)

			signed = p1.HasSigned(c)
			assert.False(t, signed)
		},
	)

	t.Run(
		"NotSigned",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var p1 *pki.PKI = setup(t)
			var p2 *pki.PKI = setup(t)
			var signed bool

			_, _, e = p1.CreateCertFor("example.com", pki.ClientCert)
			assert.NoError(t, e)

			c, _, e = p2.CreateCertFor("example.com", pki.ClientCert)
			assert.NoError(t, e)
			assert.NotNil(t, c)

			signed = p1.HasSigned(c)
			assert.False(t, signed)
		},
	)

	t.Run(
		"Signed",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var p *pki.PKI = setup(t)
			var signed bool

			c, _, e = p.CreateCertFor("example.com", pki.ClientCert)
			assert.NoError(t, e)
			assert.NotNil(t, c)

			signed = p.HasSigned(c)
			assert.True(t, signed)
		},
	)
}

func TestImportCSR(t *testing.T) {
	t.Run(
		"ErrorFailReadCSR",
		func(t *testing.T) {
			var csr *x509.CertificateRequest
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			k, e = p.CreateRSAKeyFor("example.com")
			assert.NoError(t, e)
			assert.NotNil(t, k)

			csr, e = p.CreateCSRFor("example.com", k)
			assert.NoError(t, e)
			assert.NotNil(t, csr)

			e = p.Erase()
			assert.NoError(t, e)

			e = p.ImportCSR(p.GetCSRFileFor("example.com"))
			assert.Error(t, e)
		},
	)

	t.Run(
		"ErrorFailHasCert",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.NoError(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			e = p.ImportCSR(p.GetCSRFileFor("example.com"))
			assert.Error(t, e)
		},
	)

	t.Run(
		"ErrorFailHasCSR",
		func(t *testing.T) {
			var csr *x509.CertificateRequest
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			k, e = p.CreateRSAKeyFor("example.com")
			assert.NoError(t, e)
			assert.NotNil(t, k)

			csr, e = p.CreateCSRFor("example.com", k)
			assert.NoError(t, e)
			assert.NotNil(t, csr)

			e = p.ImportCSR(p.GetCSRFileFor("example.com"))
			assert.Error(t, e)
		},
	)

	t.Run(
		"ErrorFailWriteCSR",
		func(t *testing.T) {
			var csr *x509.CertificateRequest
			var e error
			var k *rsa.PrivateKey
			var p1 *pki.PKI = setup(t)
			var p2 *pki.PKI = setup(t)

			if runtime.GOOS == "windows" {
				t.Skip("runtime OS not supported")
			}

			k, e = p1.CreateRSAKeyFor("example.com")
			assert.NoError(t, e)
			assert.NotNil(t, k)

			csr, e = p1.CreateCSRFor("example.com", k)
			assert.NoError(t, e)
			assert.NotNil(t, csr)

			// Ensure not writable
			defer func() {
				//nolint:gosec // G302 - false positive, this is a dir
				_ = os.Chmod(filepath.Join(p2.Root, "csr"), 0o700)
			}()
			//nolint:gosec // G302 - 0o500 is less than 0o600...
			e = os.Chmod(filepath.Join(p2.Root, "csr"), 0o500)
			assert.NoError(t, e)

			e = p2.ImportCSR(p1.GetCSRFileFor("example.com"))
			assert.Error(t, e)
		},
	)

	t.Run(
		"Success",
		func(t *testing.T) {
			var csr *x509.CertificateRequest
			var e error
			var k *rsa.PrivateKey
			var p1 *pki.PKI = setup(t)
			var p2 *pki.PKI = setup(t)

			k, e = p1.CreateRSAKeyFor("example.com")
			assert.NoError(t, e)
			assert.NotNil(t, k)

			csr, e = p1.CreateCSRFor("example.com", k)
			assert.NoError(t, e)
			assert.NotNil(t, csr)

			e = p2.ImportCSR(p1.GetCSRFileFor("example.com"))
			assert.NoError(t, e)
		},
	)
}

func TestIsExpired(t *testing.T) {
	type testData struct {
		days     int
		expected bool
	}

	var tests map[string]testData = map[string]testData{
		"Expired":    {-1, true},
		"NotExpired": {1, false},
	}

	for test, data := range tests {
		t.Run(
			test,
			func(t *testing.T) {
				var c *x509.Certificate
				var e error
				var k *rsa.PrivateKey
				var p *pki.PKI = setup(t)

				p.Cfg.CertDaysValid = data.days

				c, k, e = p.CreateCertFor("user", pki.ClientCert)
				assert.NoError(t, e)
				assert.NotNil(t, c)
				assert.NotNil(t, k)

				assert.Equal(t, data.expected, p.IsExpired(c))
			},
		)
	}
}

func TestIsRevoked(t *testing.T) {
	type testData struct {
		cert     *x509.Certificate
		expected bool
	}

	var c1 *x509.Certificate
	var c2 *x509.Certificate
	var e error
	var k *rsa.PrivateKey
	var p *pki.PKI = setup(t)
	var tests map[string]testData

	c1, k, e = p.CreateCertFor("user1", pki.ClientCert)
	assert.NoError(t, e)
	assert.NotNil(t, c1)
	assert.NotNil(t, k)

	c2, k, e = p.CreateCertFor("user2", pki.ClientCert)
	assert.NoError(t, e)
	assert.NotNil(t, c2)
	assert.NotNil(t, k)

	c2, e = p.RevokeCertFor("user2")
	assert.NoError(t, e)
	assert.NotNil(t, c2)

	tests = map[string]testData{
		"NotRevoked": {c1, false},
		"Revoked":    {c2, true},
	}

	for test, data := range tests {
		t.Run(
			test,
			func(t *testing.T) {
				var e error
				var revoked bool

				revoked, e = p.IsRevoked(data.cert)
				assert.NoError(t, e)
				assert.Equal(t, data.expected, revoked)
			},
		)
	}
}

func TestKeySize(t *testing.T) {
	var tests map[string]int = map[string]int{
		"2048": 2048,
		"3072": 3072,
		"4096": 4096,
	}

	for test, sz := range tests {
		t.Run(
			test,
			func(t *testing.T) {
				var ca *x509.Certificate
				var e error
				var k *rsa.PrivateKey
				var p *pki.PKI = setup(t)

				p.KeySize = sz

				ca, k, e = p.CreateCA()
				assert.NoError(t, e)
				assert.NotNil(t, ca)
				assert.NotNil(t, k)
			},
		)
	}
}

func TestNew(t *testing.T) {
	t.Run(
		"ErrorFailPKIDirectoryCreation",
		func(t *testing.T) {
			var e error
			var p *pki.PKI
			var pkiDir string = t.TempDir()
			var tmp string = filepath.Join(pkiDir, "nopki")

			// Ensure not writable
			defer func() {
				//nolint:gosec // G302 - false positive, this is a dir
				_ = os.Chmod(pkiDir, 0o700)
			}()
			//nolint:gosec // G302 - 0o500 is less than 0o600...
			e = os.Chmod(pkiDir, 0o500)
			assert.NoError(t, e)

			p, e = pki.New(tmp, pki.NewCfg())
			assert.Error(t, e)
			assert.Nil(t, p)
		},
	)

	t.Run(
		"ErrorNilConfig",
		func(t *testing.T) {
			var e error
			var p *pki.PKI

			p, e = pki.New(t.TempDir(), nil)
			assert.Error(t, e)
			assert.Nil(t, p)
		},
	)

	t.Run(
		"Success",
		func(t *testing.T) {
			setup(t)
		},
	)

	t.Run(
		"SuccessExisting",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			c, k, e = p.CreateCertFor("user", pki.ClientCert)
			assert.NoError(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.NoError(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			c, e = p.RevokeCertFor("example.com")
			assert.NoError(t, e)
			assert.NotNil(t, c)

			p.Cfg.CertDaysValid = -1

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.NoError(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			setup(t, p.Root)
		},
	)
}

func TestRevokeCert(t *testing.T) {
	t.Run(
		"ErrorNoCert",
		func(t *testing.T) {
			var e error
			var p *pki.PKI = setup(t)

			e = p.RevokeCert(nil)
			assert.Error(t, e)
		},
	)

	t.Run(
		"ErrorFailCertNotFound",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p1 *pki.PKI = setup(t)
			var p2 *pki.PKI = setup(t)

			c, k, e = p1.CreateCertFor("example.com", pki.ServerCert)
			assert.NoError(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			e = p2.RevokeCert(c)
			assert.Error(t, e)
		},
	)

	t.Run(
		"Success",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.NoError(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			e = p.RevokeCert(c)
			assert.NoError(t, e)
		},
	)
}

func TestRevokeCertFor(t *testing.T) {
	t.Run(
		"ErrorNoCN",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var p *pki.PKI = setup(t)

			c, e = p.RevokeCertFor("")
			assert.Error(t, e)
			assert.Nil(t, c)
		},
	)

	t.Run(
		"ErrorFailCertNotFound",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var p *pki.PKI = setup(t)

			c, e = p.RevokeCertFor("example.com")
			assert.Error(t, e)
			assert.Nil(t, c)
		},
	)

	t.Run(
		"ErrorMissing",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.NoError(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			// Delete cert on disk
			e = os.Remove(p.GetCertFileFor("example.com"))
			assert.NoError(t, e)

			c, e = p.RevokeCertFor("example.com")
			assert.NoError(t, e)
			assert.Nil(t, c)
		},
	)

	t.Run(
		"Success",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.NoError(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			c, e = p.RevokeCertFor("example.com")
			assert.NoError(t, e)
			assert.NotNil(t, c)
		},
	)
}

func TestSync(t *testing.T) {
	t.Run(
		"ErrorFailUnsync",
		func(t *testing.T) {
			var e error
			var p *pki.PKI = setup(t)

			if runtime.GOOS == "windows" {
				t.Skip("runtime OS not supported")
			}

			// Ensure not writable
			defer func() {
				//nolint:gosec // G302 - false positive, this is a dir
				_ = os.Chmod(p.Root, 0o700)
			}()
			//nolint:gosec // G302 - 0o500 is less than 0o600...
			e = os.Chmod(p.Root, 0o500)
			assert.NoError(t, e)

			e = p.Sync()
			assert.Error(t, e)
		},
	)

	t.Run(
		"NoCA",
		func(t *testing.T) {
			var e error
			var p *pki.PKI = setup(t)

			e = p.Sync()
			assert.NoError(t, e)
		},
	)

	t.Run(
		"ErrorFailReadExistingCA",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p1 *pki.PKI = setup(t)
			var p2 *pki.PKI

			// Create CA
			c, k, e = p1.CreateCA()
			assert.NoError(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			// Create empty file
			_, e = os.Create(p1.GetCAFile())
			assert.NoError(t, e)

			// Create second PKI instance so p2.ca == nil
			p2, e = pki.New(p1.Root, pki.NewCfg())
			assert.NoError(t, e)
			assert.NotNil(t, p2)

			e = p2.Sync()
			assert.Error(t, e)
		},
	)

	t.Run(
		"NoCerts",
		func(t *testing.T) {
			var ca *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			ca, k, e = p.CreateCA()
			assert.NoError(t, e)
			assert.NotNil(t, ca)
			assert.NotNil(t, k)

			e = p.Sync()
			assert.NoError(t, e)
		},
	)

	t.Run(
		"Success",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			p.Cfg.CertDaysValid = -1

			c, k, e = p.CreateCertFor("user1", pki.ClientCert)
			assert.NoError(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			p.Cfg.CertDaysValid = 365

			c, k, e = p.CreateCertFor("user2", pki.ClientCert)
			assert.NoError(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.NoError(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			c, e = p.RevokeCertFor("example.com")
			assert.NoError(t, e)
			assert.NotNil(t, c)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.NoError(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			e = p.Sync()
			assert.NoError(t, e)
		},
	)
}

func TestUndo(t *testing.T) {
	t.Run(
		"ErrorFailDBUndo",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.NoError(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			// Ensure not writable
			defer func() {
				_ = os.Chmod(filepath.Join(p.Root, "index.db"), 0o600)
			}()

			e = os.Chmod(filepath.Join(p.Root, "index.db"), 0o400)
			assert.NoError(t, e)

			e = p.Undo()
			assert.Error(t, e)
		},
	)

	t.Run(
		"ErrorNoEntries",
		func(t *testing.T) {
			var e error
			var p *pki.PKI = setup(t)

			e = p.Undo()
			assert.Error(t, e)
		},
	)

	t.Run(
		"Success",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.NoError(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			e = p.Undo()
			assert.NoError(t, e)
		},
	)
}
