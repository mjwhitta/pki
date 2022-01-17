package pki_test

import (
	"crypto/x509/pkix"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	assert "github.com/stretchr/testify/require"
	"gitlab.com/mjwhitta/pki"
)

func TestCfgFromFile(t *testing.T) {
	var tests = map[string]string{
		"ErrorConfigNotFound": "noexist",
		"ErrorInvalidSyntax":  "invalid",
		"ErrorInvalidValue":   "invalidint",
	}

	for test, cfg := range tests {
		t.Run(
			test,
			func(t *testing.T) {
				var c *pki.Cfg
				var e error

				c, e = pki.CfgFromFile(filepath.Join("testdata", cfg))
				assert.NotNil(t, e)
				assert.Nil(t, c)
			},
		)
	}

	// Test file not readable
	t.Run(
		"ErrorNoReadPerms",
		func(t *testing.T) {
			var c *pki.Cfg
			var e error
			var tmp string = filepath.Join("testdata", "cfg")

			if runtime.GOOS == "windows" {
				t.Skip("runtime OS not supported")
			}

			// Ensure perms get fixed b/c git
			defer os.Chmod(tmp, 0o600)

			// Ensure not readable
			e = os.Chmod(tmp, 0o200)
			assert.Nil(t, e)

			// Test not readable
			c, e = pki.CfgFromFile(tmp)
			assert.NotNil(t, e)
			assert.Nil(t, c)
		},
	)

	tests = map[string]string{
		"SuccessDefaultConfig": "cfg",
		"SuccessEmptyConfig":   "emptycfg",
	}

	for test, cfg := range tests {
		t.Run(
			test,
			func(t *testing.T) {
				var c *pki.Cfg
				var e error

				c, e = pki.CfgFromFile(filepath.Join("testdata", cfg))
				assert.Nil(t, e)
				assert.NotNil(t, c)
			},
		)
	}
}

func TestCommonName(t *testing.T) {
	var c *pki.Cfg = pki.NewCfg()

	c.CommonName("")
	assert.Contains(t, c.String(), "Self-signed CA")
}

func TestSetOption(t *testing.T) {
	var tests = map[string][]string{
		"ErrorInvalidCADays":   {"cadays", "test"},
		"ErrorInvalidCertDays": {"certdays", "test"},
		"ErrorInvalidOption":   {"test", "true"},
	}

	for test, data := range tests {
		t.Run(
			test,
			func(t *testing.T) {
				var c *pki.Cfg = pki.NewCfg()
				var e error = c.SetOption(data[0], data[1])

				assert.NotNil(t, e)
			},
		)
	}
}

func TestString(t *testing.T) {
	var b []byte
	var c *pki.Cfg
	var e error
	var expected string
	var tmp string = filepath.Join("testdata", "cfg")

	// Get expected from file
	b, e = ioutil.ReadFile(tmp)
	assert.Nil(t, e)
	assert.NotNil(t, b)

	// Use default config
	c, e = pki.CfgFromFile(tmp)
	assert.Nil(t, e)
	assert.NotNil(t, c)

	expected = strings.TrimSpace(string(b))
	assert.Equal(t, expected, c.String())

	// Use empty config
	c, e = pki.CfgFromFile(filepath.Join("testdata", "emptycfg"))
	assert.Nil(t, e)
	assert.NotNil(t, c)

	// Configure some corner cases
	c.CADaysValid = 364
	c.CertDaysValid = 364

	expected = strings.Join(
		[]string{
			"# Adjust and uncomment these values as needed",
			"",
			"cacn = Self-signed CA",
			"cadays = 364",
			"certdays = 364",
		},
		"\n",
	)
	assert.Equal(t, expected, c.String())
}

func TestSubject(t *testing.T) {
	t.Run(
		"DefaultSubject",
		func(t *testing.T) {
			var c *pki.Cfg = pki.NewCfg()
			var expected = pkix.Name{
				CommonName:         "Self-signed CA",
				Country:            []string{""},
				Locality:           []string{""},
				Organization:       []string{""},
				OrganizationalUnit: []string{""},
				Province:           []string{""},
			}

			assert.Equal(t, expected, c.Subject())
		},
	)

	t.Run(
		"ConfiguredSubject",
		func(t *testing.T) {
			var c *pki.Cfg = pki.NewCfg()
			var expected = pkix.Name{
				CommonName:         "CN",
				Country:            []string{"C"},
				Locality:           []string{"L"},
				Organization:       []string{"O"},
				OrganizationalUnit: []string{"OU"},
				Province:           []string{"ST"},
			}

			c.City("L")
			c.CommonName("CN")
			c.Company("O")
			c.Country("C")
			c.State("ST")
			c.Unit("OU")

			assert.Equal(t, expected, c.Subject())
		},
	)

	t.Run(
		"OverrideCNInSubject",
		func(t *testing.T) {
			var c *pki.Cfg = pki.NewCfg()
			var expected = pkix.Name{
				CommonName:         "CN",
				Country:            []string{""},
				Locality:           []string{""},
				Organization:       []string{""},
				OrganizationalUnit: []string{""},
				Province:           []string{""},
			}

			assert.Equal(t, expected, c.Subject("CN"))
		},
	)
}
