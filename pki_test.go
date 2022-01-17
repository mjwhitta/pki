package pki_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	assert "github.com/stretchr/testify/require"
	"gitlab.com/mjwhitta/pki"
)

func setup(t *testing.T, dirs ...string) *pki.PKI {
	var dir string = tempDir(t)
	var e error
	var p *pki.PKI

	if len(dirs) != 0 {
		dir = dirs[0]
	}

	p, e = pki.New(dir, pki.NewCfg())
	assert.Nil(t, e)
	assert.NotNil(t, p)

	p.KeySize = 1024

	return p
}

// This is better than t.TempDir() b/c it's self-contained (so doesn't
// break GitLab runners) and it ensures the permissions are fixed
// before trying to delete during Cleanup().
func tempDir(t *testing.T) string {
	var b []byte = make([]byte, 32)
	var e error
	var out string

	if _, e = rand.Read(b); e != nil {
		t.Fatal("could not create random temp directory")
	}

	out = filepath.Join("testdata", "Test_"+hex.EncodeToString(b))

	t.Cleanup(
		func() {
			// Ensure temp dir can be deleted
			filepath.WalkDir(
				out,
				func(path string, d fs.DirEntry, e error) error {
					if e != nil {
						return e
					}

					if d.IsDir() {
						e = os.Chmod(path, 0o700)
					} else {
						e = os.Chmod(path, 0o600)
					}
					assert.Nil(t, e)

					return nil
				},
			)

			os.RemoveAll(out)
		},
	)

	return out
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
			e = os.Chmod(filepath.Join(p.Root, "private"), 0o500)
			assert.Nil(t, e)

			ca, k, e = p.CreateCA()
			assert.NotNil(t, e)
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
			e = os.Chmod(filepath.Join(p.Root, "ca"), 0o500)
			assert.Nil(t, e)

			ca, k, e = p.CreateCA()
			assert.NotNil(t, e)
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

			if runtime.GOOS == "windows" {
				t.Skip("runtime OS not supported")
			}

			ca, k, e = p.CreateCA()
			assert.Nil(t, e)
			assert.NotNil(t, ca)
			assert.NotNil(t, k)

			// Ensure not readable
			e = os.Chmod(p.GetCAFile(), 0o200)
			assert.Nil(t, e)

			ca, k, e = p.CreateCA()
			assert.NotNil(t, e)
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
			assert.Nil(t, e)
			assert.NotNil(t, ca)
			assert.NotNil(t, k)
		},
	)
}

func TestCreateCert(t *testing.T) {
	type testData struct {
		certType pki.CertType
		cn       string
	}

	var p *pki.PKI = setup(t)
	var tests = map[string]testData{
		"CreateClientCert": {
			certType: pki.ClientCert,
			cn:       "user",
		},
		"GetClientCert": {
			certType: pki.ClientCert,
			cn:       "user",
		},
		"CreateServerCert": {
			certType: pki.ServerCert,
			cn:       "example.com",
		},
	}

	t.Run(
		"ErrorFailReadExistingCert",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			if runtime.GOOS == "windows" {
				t.Skip("runtime OS not supported")
			}

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.Nil(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			// Ensure not readable
			e = os.Chmod(p.GetCertFileFor("example.com"), 0o200)
			assert.Nil(t, e)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.NotNil(t, e)
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
			assert.NotNil(t, e)
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
				assert.Nil(t, e)
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
			assert.NotNil(t, e)
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
			assert.NotNil(t, e)
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

			k, e = p.CreateRSAKeyFor("example.com")
			assert.Nil(t, e)
			assert.NotNil(t, k)

			// Ensure not writable
			e = os.Chmod(filepath.Join(p.Root, "csr"), 0o500)
			assert.Nil(t, e)

			csr, e = p.CreateCSRFor("example.com", k)
			assert.NotNil(t, e)
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
			assert.Nil(t, e)
			assert.NotNil(t, k)

			csr, e = p.CreateCSRFor("example.com", k)
			assert.Nil(t, e)
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

			// Ensure not writable
			e = os.Chmod(filepath.Join(p.Root, "private"), 0o500)
			assert.Nil(t, e)

			k, e = p.CreateRSAKeyFor("example.com")
			assert.NotNil(t, e)
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
			assert.NotNil(t, e)
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
			assert.Nil(t, e)
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

			// Ensure not writable
			e = os.Chmod(p.Root, 0o500)
			assert.Nil(t, e)

			e = p.Erase()
			assert.NotNil(t, e)
		},
	)

	t.Run(
		"Success",
		func(t *testing.T) {
			var e error
			var p *pki.PKI = setup(t)

			e = p.Erase()
			assert.Nil(t, e)
		},
	)
}

func TestGetFiles(t *testing.T) {
	var p *pki.PKI = setup(t)
	var tests = map[string]func(cn string) string{
		"CertNoCN": p.GetCertFileFor,
		"CSRNoCN":  p.GetCSRFileFor,
		"KeyNoCN":  p.GetKeyFileFor,
	}

	for test, f := range tests {
		t.Run(
			test,
			func(t *testing.T) {
				var fn string = f("")

				assert.Equal(t, "", fn)
			},
		)
	}

	tests = map[string]func(cn string) string{
		"SuccessCert": p.GetCertFileFor,
		"SuccessCSR":  p.GetCSRFileFor,
		"SuccessKey":  p.GetKeyFileFor,
	}

	for test, f := range tests {
		t.Run(
			test,
			func(t *testing.T) {
				var fn string = f("example.com")

				assert.NotEqual(t, "", fn)
			},
		)
	}
}

func TestHasSigned(t *testing.T) {
	t.Run(
		"FalseNil",
		func(t *testing.T) {
			var e error
			var p *pki.PKI = setup(t)
			var signed bool

			_, _, e = p.CreateCA()
			assert.Nil(t, e)

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
			assert.Nil(t, e)
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
			assert.Nil(t, e)

			c, _, e = p2.CreateCertFor("example.com", pki.ClientCert)
			assert.Nil(t, e)
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
			assert.Nil(t, e)
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
			assert.Nil(t, e)
			assert.NotNil(t, k)

			csr, e = p.CreateCSRFor("example.com", k)
			assert.Nil(t, e)
			assert.NotNil(t, csr)

			e = p.Erase()
			assert.Nil(t, e)

			e = p.ImportCSR(p.GetCSRFileFor("example.com"))
			assert.NotNil(t, e)
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
			assert.Nil(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			e = p.ImportCSR(p.GetCSRFileFor("example.com"))
			assert.NotNil(t, e)
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
			assert.Nil(t, e)
			assert.NotNil(t, k)

			csr, e = p.CreateCSRFor("example.com", k)
			assert.Nil(t, e)
			assert.NotNil(t, csr)

			e = p.ImportCSR(p.GetCSRFileFor("example.com"))
			assert.NotNil(t, e)
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

			k, e = p1.CreateRSAKeyFor("example.com")
			assert.Nil(t, e)
			assert.NotNil(t, k)

			csr, e = p1.CreateCSRFor("example.com", k)
			assert.Nil(t, e)
			assert.NotNil(t, csr)

			// Ensure not writable
			e = os.Chmod(filepath.Join(p2.Root, "csr"), 0o500)
			assert.Nil(t, e)

			e = p2.ImportCSR(p1.GetCSRFileFor("example.com"))
			assert.NotNil(t, e)
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
			assert.Nil(t, e)
			assert.NotNil(t, k)

			csr, e = p1.CreateCSRFor("example.com", k)
			assert.Nil(t, e)
			assert.NotNil(t, csr)

			e = p2.ImportCSR(p1.GetCSRFileFor("example.com"))
			assert.Nil(t, e)
		},
	)
}

func TestIsExpired(t *testing.T) {
	type testData struct {
		days     int
		expected bool
	}

	var tests = map[string]testData{
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
				assert.Nil(t, e)
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
	assert.Nil(t, e)
	assert.NotNil(t, c1)
	assert.NotNil(t, k)

	c2, k, e = p.CreateCertFor("user2", pki.ClientCert)
	assert.Nil(t, e)
	assert.NotNil(t, c2)
	assert.NotNil(t, k)

	c2, e = p.RevokeCertFor("user2")
	assert.Nil(t, e)
	assert.NotNil(t, c2)

	tests = map[string]testData{
		"NotRevoked": {c1, false},
		"Revoked":    {c2, true},
	}

	for test, data := range tests {
		t.Run(
			test,
			func(t *testing.T) {
				assert.Equal(t, data.expected, p.IsRevoked(data.cert))
			},
		)
	}
}

func TestKeySize(t *testing.T) {
	var tests = map[string]int{
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
				assert.Nil(t, e)
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
			var pkiDir string = tempDir(t)
			var tmp string = filepath.Join(pkiDir, "nopki")

			// Ensure not writable
			os.MkdirAll(pkiDir, 0o400)

			p, e = pki.New(tmp, pki.NewCfg())
			assert.NotNil(t, e)
			assert.Nil(t, p)
		},
	)

	t.Run(
		"ErrorNilConfig",
		func(t *testing.T) {
			var e error
			var p *pki.PKI

			p, e = pki.New(tempDir(t), nil)
			assert.NotNil(t, e)
			assert.Nil(t, p)
		},
	)

	t.Run(
		"ErrorFailDBCreation",
		func(t *testing.T) {
			var e error
			var p *pki.PKI
			var pkiDir string = tempDir(t)

			// Ensure not writable
			os.MkdirAll(pkiDir, 0o400)

			p, e = pki.New(pkiDir, pki.NewCfg())
			assert.NotNil(t, e)
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
			assert.Nil(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.Nil(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			c, e = p.RevokeCertFor("example.com")
			assert.Nil(t, e)
			assert.NotNil(t, c)

			p.Cfg.CertDaysValid = -1

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.Nil(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			setup(t, p.Root)
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
			assert.NotNil(t, e)
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
			assert.NotNil(t, e)
			assert.Nil(t, c)
		},
	)

	t.Run(
		"ErrorFailDeleteCert",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.Nil(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			// Ensure not writable
			e = os.Chmod(filepath.Join(p.Root, "certs"), 0o500)
			assert.Nil(t, e)

			c, e = p.RevokeCertFor("example.com")
			assert.NotNil(t, e)
			assert.Nil(t, c)
		},
	)

	t.Run(
		"ErrorFailDeleteCSR",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.Nil(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			// Ensure not writable
			e = os.Chmod(filepath.Join(p.Root, "csr"), 0o500)
			assert.Nil(t, e)

			c, e = p.RevokeCertFor("example.com")
			assert.NotNil(t, e)
			assert.Nil(t, c)
		},
	)

	t.Run(
		"ErrorFailDeleteKey",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.Nil(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			// Ensure not writable
			e = os.Chmod(filepath.Join(p.Root, "private"), 0o500)
			assert.Nil(t, e)

			c, e = p.RevokeCertFor("example.com")
			assert.NotNil(t, e)
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
			assert.Nil(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			c, e = p.RevokeCertFor("example.com")
			assert.Nil(t, e)
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

			// Ensure not writable
			e = os.Chmod(p.Root, 0o500)
			assert.Nil(t, e)

			e = p.Sync()
			assert.NotNil(t, e)
		},
	)

	t.Run(
		"NoCA",
		func(t *testing.T) {
			var e error
			var p *pki.PKI = setup(t)

			e = p.Sync()
			assert.Nil(t, e)
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
			assert.Nil(t, e)
			assert.NotNil(t, ca)
			assert.NotNil(t, k)

			e = p.Sync()
			assert.Nil(t, e)
		},
	)

	t.Run(
		"Success",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			c, k, e = p.CreateCertFor("user", pki.ClientCert)
			assert.Nil(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.Nil(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			e = p.Sync()
			assert.Nil(t, e)
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
			assert.Nil(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			// Ensure not writable
			e = os.Chmod(filepath.Join(p.Root, "index.db"), 0o400)
			assert.Nil(t, e)

			e = p.Undo()
			assert.NotNil(t, e)
		},
	)

	t.Run(
		"ErrorNoEntries",
		func(t *testing.T) {
			var e error
			var p *pki.PKI = setup(t)

			e = p.Undo()
			assert.NotNil(t, e)
		},
	)

	t.Run(
		"ErrorFailReadExistingCert",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			if runtime.GOOS == "windows" {
				t.Skip("runtime OS not supported")
			}

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.Nil(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			// Ensure not readable
			e = os.Chmod(p.GetCertFileFor("example.com"), 0o200)
			assert.Nil(t, e)

			e = p.Undo()
			assert.NotNil(t, e)
		},
	)

	t.Run(
		"ErrorFailDeleteCert",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.Nil(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			// Ensure not writable
			e = os.Chmod(filepath.Join(p.Root, "certs"), 0o500)
			assert.Nil(t, e)

			e = p.Undo()
			assert.NotNil(t, e)
		},
	)

	t.Run(
		"ErrorFailDeleteCSR",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.Nil(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			// Ensure not writable
			e = os.Chmod(filepath.Join(p.Root, "csr"), 0o500)
			assert.Nil(t, e)

			e = p.Undo()
			assert.NotNil(t, e)
		},
	)

	t.Run(
		"ErrorFailDeleteKey",
		func(t *testing.T) {
			var c *x509.Certificate
			var e error
			var k *rsa.PrivateKey
			var p *pki.PKI = setup(t)

			c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
			assert.Nil(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			// Ensure not writable
			e = os.Chmod(filepath.Join(p.Root, "private"), 0o500)
			assert.Nil(t, e)

			e = p.Undo()
			assert.NotNil(t, e)
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
			assert.Nil(t, e)
			assert.NotNil(t, c)
			assert.NotNil(t, k)

			e = p.Undo()
			assert.Nil(t, e)
		},
	)
}
